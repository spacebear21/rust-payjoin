import "dart:convert";
import "dart:typed_data";

import "package:http/http.dart" as http;
import 'package:test/test.dart';
import "package:convert/convert.dart";

import "../lib/payjoin_ffi.dart" as payjoin;
import "../lib/bitcoin.dart" as bitcoin;

late payjoin.BitcoindEnv env;
late payjoin.BitcoindInstance bitcoind;
late payjoin.RpcClient receiver;
late payjoin.RpcClient sender;

class InMemoryReceiverPersister
    implements payjoin.JsonReceiverSessionPersister {
  final String id;
  final List<String> events = [];
  bool closed = false;

  InMemoryReceiverPersister(this.id);

  @override
  void save(String event) {
    events.add(event);
  }

  @override
  List<String> load() {
    return events;
  }

  @override
  void close() {
    closed = true;
  }
}

class InMemorySenderPersister implements payjoin.JsonSenderSessionPersister {
  final String id;
  final List<String> events = [];
  bool closed = false;

  InMemorySenderPersister(this.id);

  @override
  void save(String event) {
    events.add(event);
  }

  @override
  List<String> load() {
    return events;
  }

  @override
  void close() {
    closed = true;
  }
}

class MempoolAcceptanceCallback implements payjoin.CanBroadcast {
  final payjoin.RpcClient connection;

  MempoolAcceptanceCallback(this.connection);

  @override
  bool callback(Uint8List tx) {
    try {
      final hexTx = bytesToHex(tx);
      final resultJson = connection.call("testmempoolaccept", ['[$hexTx]']);
      final decoded = jsonDecode(resultJson);
      return decoded[0]['allowed'] == true;
    } catch (e) {
      print("An error occurred: $e");
      return false;
    }
  }

  String bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}

class IsScriptOwnedCallback implements payjoin.IsScriptOwned {
  final payjoin.RpcClient connection;

  IsScriptOwnedCallback(this.connection);

  @override
  bool callback(Uint8List script) {
    try {
      final scriptObj = bitcoin.Script(script);
      final address =
          bitcoin.Address.fromScript(scriptObj, bitcoin.Network.regtest);
      final result = connection.call("getaddressinfo", [address.toString()]);
      final decoded = jsonDecode(result);
      return decoded["ismone"] == true;
    } catch (e) {
      print("An error occurred: $e");
      return false;
    }
  }
}

class CheckInputsNotSeenCallback implements payjoin.IsOutputKnown {
  final payjoin.RpcClient connection;

  CheckInputsNotSeenCallback(this.connection);

  @override
  bool callback(_outpoint) {
    return false;
  }
}

class ProcessPsbtCallback implements payjoin.ProcessPsbt {
  final payjoin.RpcClient connection;

  ProcessPsbtCallback(this.connection);

  @override
  String callback(String psbt) {
    final res = jsonDecode(connection.call("walletprocesspsbt", [psbt]));
    return res["psbt"];
  }
}

payjoin.Initialized create_receiver_context(
    address, directory, ohttp_keys, expiry, persister) {
  var receiver = payjoin.UninitializedReceiver()
      .createSession(address, directory, ohttp_keys, null)
      .save(persister);
  return receiver;
}

bitcoin.Psbt build_sweep_psbt(payjoin.RpcClient sender, payjoin.PjUri pj_uri) {
  var outputs = <String, dynamic>{};
  outputs[pj_uri.address()] = 50;
  var psbt = jsonDecode(sender.call("walletcreatefundedpsbt", [
    jsonEncode([]),
    jsonEncode(outputs),
    jsonEncode(0),
    jsonEncode({
      "lockUnspents": true,
      "fee_rate": 10,
      "subtract_fee_from_outputs": [0]
    })
  ]));
  return jsonDecode(sender.call("walletprocesspsbt",
      [psbt, jsonEncode(true), jsonEncode("ALL"), jsonEncode(false)]))["psbt"];
}

List<payjoin.InputPair> get_inputs(payjoin.RpcClient rpc_connection) {
  var utxos = jsonDecode(rpc_connection.call("listunspent", [null]));
  List<payjoin.InputPair> inputs = [];
  for (var utxo in utxos) {
    var txin = bitcoin.TxIn.inner(
        bitcoin.OutPoint.inner(utxo["txid"], utxo["vout"]),
        bitcoin.Script(Uint8List.fromList([])),
        0, []);
    var raw_tx = jsonDecode(rpc_connection.call("gettransaction",
        [jsonEncode(utxo["txid"]), jsonEncode(true), jsonEncode(true)]));
    var prev_out = raw_tx["decoded"]["vout"][utxo["vout"]];
    var prev_spk = bitcoin.Script(Uint8List.fromList(
        hex.decode(prev_out["ScriptPubkey"]["hex"].toString())));
    var prev_amount = bitcoin.Amount.fromBtc(prev_out["value"]);
    var tx_out = bitcoin.TxOut.inner(prev_amount, prev_spk);
    var psbt_in = payjoin.PsbtInput.inner(tx_out, null, null);
    inputs.add(payjoin.InputPair(txin, psbt_in));
  }

  return inputs;
}

process_provisional_proposal(
    proposal, InMemoryReceiverPersister recv_persister) async {
  final payjoin_proposal = proposal
      .finalizeProposal(ProcessPsbtCallback(receiver), 1, 10)
      .save(recv_persister);
  return payjoin.PayjoinProposalReceiveSession(payjoin_proposal);
}

process_wants_inputs(proposal, InMemoryReceiverPersister recv_persister) async {
  final provisional_proposal = proposal
      .contributeInputs(get_inputs(receiver))
      .commitInputs()
      .save(recv_persister);
  return await process_provisional_proposal(
      provisional_proposal, recv_persister);
}

process_wants_outputs(
    proposal, InMemoryReceiverPersister recv_persister) async {
  final wants_inputs = proposal.commitOutputs().save(recv_persister);
  return await process_wants_inputs(wants_inputs, recv_persister);
}

process_outputs_unknown(
    proposal, InMemoryReceiverPersister recv_persister) async {
  final wants_outputs = proposal
      .identifyReceiverOutputs(IsScriptOwnedCallback(receiver))
      .save(recv_persister);
  return await process_wants_outputs(wants_outputs, recv_persister);
}

process_maybe_inputs_seen(
    proposal, InMemoryReceiverPersister recv_persister) async {
  final outputs_unknown = proposal
      .checkNoInputsSeenBefore(CheckInputsNotSeenCallback(receiver))
      .save(recv_persister);
  return await process_outputs_unknown(outputs_unknown, recv_persister);
}

process_maybe_inputs_owned(
    proposal, InMemoryReceiverPersister recv_persister) async {
  final maybe_inputs_owned = proposal
      .checkInputsNotOwned(IsScriptOwnedCallback(receiver))
      .save(recv_persister);
  return await process_maybe_inputs_seen(maybe_inputs_owned, recv_persister);
}

process_unchecked_proposal(
    proposal, InMemoryReceiverPersister recv_persister) async {
  final unchecked_proposal = proposal
      .checkBroadcastSuitability(null, MempoolAcceptanceCallback(receiver))
      .save(recv_persister);
  return await process_maybe_inputs_owned(unchecked_proposal, recv_persister);
}

Future<payjoin.ReceiveSession?> retrieve_receiver_proposal(receiver,
    InMemoryReceiverPersister recv_persister, payjoin.Url ohttp_relay) async {
  var agent = http.Client();
  var request = receiver.extractReq(ohttp_relay.toString());
  var response = await agent.post(Uri.https(request.request.url.toString()),
      headers: {"Content-Type": request.request.contentType});
  var res = receiver
      .processRes(Uint8List.fromList(utf8.encode(response.body)),
          request.clientResponse)
      .save(recv_persister);
  if (res.isNone()) {
    return null;
  }
  var proposal = res.success();
  return await process_unchecked_proposal(proposal, recv_persister);
}

Future<payjoin.ReceiveSession?> process_receiver_proposal(
    payjoin.ReceiveSession receiver,
    InMemoryReceiverPersister recv_persister,
    payjoin.Url ohttp_relay) async {
  if (receiver is payjoin.Initialized) {
    var res =
        await retrieve_receiver_proposal(receiver, recv_persister, ohttp_relay);
    if (res == null) {
      return null;
    }
    return res;
  }

  if (receiver is payjoin.UncheckedProposal) {
    return await process_unchecked_proposal(receiver, recv_persister);
  }
  if (receiver is payjoin.MaybeInputsOwned) {
    return await process_maybe_inputs_owned(receiver, recv_persister);
  }
  if (receiver is payjoin.MaybeInputsSeen) {
    return await process_maybe_inputs_seen(receiver, recv_persister);
  }
  if (receiver is payjoin.OutputsUnknown) {
    return await process_outputs_unknown(receiver, recv_persister);
  }
  if (receiver is payjoin.WantsOutputs) {
    return await process_wants_outputs(receiver, recv_persister);
  }
  if (receiver is payjoin.WantsInputs) {
    return await process_wants_inputs(receiver, recv_persister);
  }
  if (receiver is payjoin.ProvisionalProposal) {
    return await process_provisional_proposal(receiver, recv_persister);
  }
  if (receiver is payjoin.PayjoinProposal) {
    return receiver;
  }

  throw Exception("Unknown receiver state: $receiver");
}

void main() {
  group('Test integration', () {
    test('Test integration v2 to v2', () async {
      env = payjoin.initBitcoindSenderReceiver();
      bitcoind = env.getBitcoind();
      receiver = env.getReceiver();
      sender = env.getSender();
      var receiver_address = bitcoin.Address(
          jsonEncode(receiver.call("getnewaddress", [null])),
          bitcoin.Network.regtest);
      var services = payjoin.TestServices.initialize();

      services.waitForServicesReady();
      var directory = services.directoryUrl();
      var ohttp_keys = services.fetchOhttpKeys();
      var ohttp_relay = services.ohttpRelayUrl();
      var agent = http.Client();

      // **********************
      // Inside the Receiver:
      var recv_persister = InMemoryReceiverPersister("1");
      var sender_persister = InMemorySenderPersister("1");
      var session = create_receiver_context(
          receiver_address, directory, ohttp_keys, null, recv_persister);
      // var process_response =
      //     await process_receiver_proposal(session, recv_persister, ohttp_relay);
      // expect(process_response, isNull);

      // **********************
      // Inside the Sender:
      // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
      var pj_uri = session.pjUri();
      var psbt = build_sweep_psbt(sender, pj_uri);
      payjoin.WithReplyKey req_ctx =
          payjoin.SenderBuilder(psbt.toString(), pj_uri)
              .buildRecommended(1000)
              .save(sender_persister);
      payjoin.RequestV2PostContext request =
          req_ctx.extractV2(ohttp_relay.toString());
      var response = await agent.post(Uri.https(request.request.url.toString()),
          headers: {"Content-Type": request.request.contentType},
          body: request.request.body);
      payjoin.V2GetContext send_ctx = req_ctx
          .processResponse(
              Uint8List.fromList(utf8.encode(response.body)), request.context)
          .save(sender_persister);
      // POST Original PSBT

      // **********************
      // Inside the Receiver:

      // GET fallback psbt
      payjoin.ReceiveSession? payjoin_proposal =
          await process_receiver_proposal(
              payjoin.InitializedReceiveSession(session),
              recv_persister,
              ohttp_relay);
      expect(payjoin_proposal, isNotNull);
      expect(payjoin_proposal, isA<payjoin.PayjoinProposal>());

      payjoin.PayjoinProposal proposal =
          payjoin_proposal as payjoin.PayjoinProposal;
      payjoin.RequestResponse request_response =
          proposal.extractReq(ohttp_relay.toString());
      var fallback_response = await agent.post(
          Uri.https(request_response.request.url.toString()),
          headers: {"Content-Type": request_response.request.contentType},
          body: request_response.request.body);
      proposal.processRes(
          Uint8List.fromList(utf8.encode(fallback_response.body)),
          request_response.clientResponse);

      // **********************
      // Inside the Sender:
      // Sender checks, isngs, finalizes, extracts, and broadcasts
      // Replay post fallback to get the response
      payjoin.RequestOhttpContext ohttp_context_request =
          send_ctx.extractReq(ohttp_relay.toString());
      var final_response = await agent.post(
          Uri.https(ohttp_context_request.request.url.toString()),
          headers: {"Content-Type": ohttp_context_request.request.contentType},
          body: ohttp_context_request.request.body);
      var checked_payjoin_proposal_psbt = send_ctx
          .processResponse(Uint8List.fromList(utf8.encode(final_response.body)),
              ohttp_context_request.ohttpCtx)
          .save(sender_persister)
          .success();
      print("checked_payjoin_proposal: $checked_payjoin_proposal_psbt");
      expect(checked_payjoin_proposal_psbt, isNotNull);
      var payjoin_psbt = jsonDecode(sender.call("walletprocesspsbt",
          [checked_payjoin_proposal_psbt?.serializeBase64()]))["psbt"];
      var final_psbt = jsonDecode(sender
          .call("finalizepsbt", [payjoin_psbt, jsonEncode(false)]))["psbt"];
      var payjoin_tx = bitcoin.Psbt.deserializeBase64(final_psbt).extractTx();
      sender.call("sendrawtransaction",
          [jsonEncode(hex.encode(payjoin_tx.serialize()))]);

      // Check resulting transaction and balances
      var network_fees =
          bitcoin.Psbt.deserializeBase64(final_psbt).fee().toBtc();
      // Sender sent the entire value of their utxo to the receiver (minus fees)
      expect(payjoin_tx.input().length, 2);
      expect(payjoin_tx.output().length, 1);
      expect(
          jsonDecode(receiver.call("getbalances", [null]))["mine"]
              ["untrusted_pending"],
          100 - network_fees);
      expect(sender.call("getbalance", [null]), 0);
    });
  });
}
