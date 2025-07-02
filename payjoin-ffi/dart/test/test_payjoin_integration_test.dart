import "dart:typed_data";

import "package:http/http.dart" as http;
import 'package:test/test.dart';
import "dart:convert";

import "../lib/payjoin_ffi.dart" as payjoin;
import "../lib/bitcoin.dart" as bitcoin;

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

abstract class AlwaysTrueCanBroadcast implements payjoin.CanBroadcast {
  @override
  bool callback(
    Uint8List tx,
  ) =>
      true;
}

abstract class AlwaysInputsNotSeen implements payjoin.MaybeInputsSeen {
  @override
  bool callback() => false;
}

late payjoin.BitcoindEnv env;
late payjoin.BitcoindInstance bitcoind;
late payjoin.RpcClient receiver;
late payjoin.RpcClient sender;

payjoin.WithContext create_receiver_context(
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

// payjoin.PayjoinProposal process_provisional_proposal(
//     payjoin.ProvisionalProposal proposal,
//     InMemoryReceiverPersister recv_persister) async {
//   final payjoin_proposal = proposal
//       .finalizeProposal(
//           processPsbt, minFeerateSatPerVb, maxEffectiveFeeRateSatPerVb)
//       .save(recv_persister);
//   return payjoin.ReceiverSessionEvent.PAYJOIN_PROPOSAL(payjoin_proposal);
// }
//
// payjoin.ProvisionalProposal process_wants_inputs(payjoin.WantsInputs proposal,
//     InMemoryReceiverPersister recv_persister) async {
//   final provisional_proposal = proposal
//       .contributeInputs(replacementInputs)
//       .commitInputs()
//       .save(recv_persister);
//   return await process_provisional_proposal(
//       provisional_proposal, recv_persister);
// }
//
// payjoin.WantsInputs process_wants_ouputs(payjoin.WantsOutputs proposal,
//     InMemoryReceiverPersister recv_persister) async {
//   final wants_inputs = proposal.commitOutputs().save(recv_persister);
//   return await process_wants_inputs(wants_inputs, recv_persister);
// }
//
// payjoin.WantsOutputs process_outputs_unknown(payjoin.OutputsUnknown proposal,
//     InMemoryReceiverPersister recv_persister) async {
//   final wants_outputs =
//       proposal.identifyReceiverOutputs(isReceiverOutput).save(recv_persister);
//   return await process_wants_inputs(wants_outputs, recv_persister);
// }
//
// payjoin.OutputsUnknown process_maybe_inputs_seen(
//     payjoin.MaybeInputsSeen proposal,
//     InMemoryReceiverPersister recv_persister) async {
//   final outputs_unknown =
//       proposal.checkNoInputsSeenBefore(isKnown).save(recv_persister);
//   return await process_outputs_unknown(outputs_unknown, recv_persister);
// }
//
// payjoin.MaybeInputsSeen process_maybe_inputs_owned(
//     MaybeInputsOwned proposal, InMemoryReceiverPersister recv_persister) async {
//   final alwaysInputsNotSeen = AlwaysInputsNotSeen;
//   final maybe_inputs_owned =
//       proposal.checkInputsNotOwned(alwaysInputsNotSeen).save(recv_persister);
//   return await process_maybe_inputs_seen(maybe_inputs_owned, recv_persister);
// }
//
// payjoin.MaybeInputsOwned process_unchecked_proposal(
//     payjoin.UncheckedProposal proposal,
//     InMemoryReceiverPersister recv_persister) async {
//   final canAlwaysBroadcast = AlwaysTrueCanBroadcast;
//   final receiver = proposal
//       .checkBroadcastSuitability(null, canAlwaysBroadcast)
//       .save(recv_persister);
//   return await process_maybe_inputs_owned(receiver, recv_persister);
// }
//
// payjoin.ReceiverSessionEvent retrieve_receiver_proposal(
//     payjoin.WithContext receiver,
//     InMemoryReceiverPersister recv_persister,
//     payjoin.Url ohttp_relay) async {
//   var agent = http.Client();
//   var request = receiver.extractReq(ohttp_relay.toString());
//   var response = await agent.post(request.request.url,
//       headers: {"Content-Type": request.request.contentType});
//   var res = receiver
//       .processRes(response.body.toString(), request.clientResponse)
//       .save(recv_persister);
//   if (res.isNone()) {
//     return null;
//   }
//   var proposal = res.success();
//   return await process_unchecked_proposal(proposal, recv_persister);
// }

payjoin.ReceiverSessionEvent? process_receiver_proposal(payjoin.ReceiverSessionEvent receiver, InMemoryReceiverPersister recv_persister, payjoin.Url ohttp_relay) {
  if receiver is payjoin.WithContext {
  var res = await retrieve
}
}

void main() {
  group('Test integration', () {
    test('Test integration v2 to v2', () async {
      var receiver_address = bitcoin.Address(
          jsonEncode(receiver.call("getnewaddress", [])),
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
      var payjoin_proposal = await process_receiver_proposal();
      expect(payjoin_proposal, isNotNull);
      expect(payjoin_proposal, isA<payjoin.PayjoinProposal>());

      payjoin_proposal = payjoin_proposal.inner;
      payjoin.RequestResponse request =
          payjoin_proposal.extractReq(ohttp_relay.toString());
      var response = await agent.post(Uri.https(request.request.url.toString()),
          headers: {"Content-Type": request.request.contentType},
          body: request.request.body);
      payjoin_proposal.processRes(response.body, request.context);

      expect(true, false);
    });
  });
}
