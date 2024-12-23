use std::str::FromStr;

use bitcoin::base64::prelude::BASE64_URL_SAFE_NO_PAD;
use bitcoin::base64::Engine;
use url::Url;

use super::error::ParseReceiverPubkeyError;
use crate::hpke::HpkePublicKey;
use crate::OhttpKeys;

/// Parse and set fragment parameters from `&pj=` URI parameter URLs
pub(crate) trait UrlExt {
    fn receiver_pubkey(&self) -> Result<HpkePublicKey, ParseReceiverPubkeyError>;
    fn set_receiver_pubkey(&mut self, exp: Option<HpkePublicKey>);
    fn ohttp(&self) -> Option<OhttpKeys>;
    fn set_ohttp(&mut self, ohttp: Option<OhttpKeys>);
    fn exp(&self) -> Option<std::time::SystemTime>;
    fn set_exp(&mut self, exp: Option<std::time::SystemTime>);
}

impl UrlExt for Url {
    /// Retrieve the receiver's public key from the URL fragment
    fn receiver_pubkey(&self) -> Result<HpkePublicKey, ParseReceiverPubkeyError> {
        let value = get_param(self, "rk=", |v| Some(v.to_owned()))
            .ok_or(ParseReceiverPubkeyError::MissingPubkey)?;

        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(&value)
            .map_err(ParseReceiverPubkeyError::PubkeyNotBase64)?;

        HpkePublicKey::from_compressed_bytes(&decoded)
            .map_err(ParseReceiverPubkeyError::InvalidPubkey)
    }

    /// Set the receiver's public key in the URL fragment
    fn set_receiver_pubkey(&mut self, pubkey: Option<HpkePublicKey>) {
        set_param(
            self,
            "rk=",
            pubkey.map(|k| BASE64_URL_SAFE_NO_PAD.encode(k.to_compressed_bytes())),
        )
    }

    /// Retrieve the ohttp parameter from the URL fragment
    fn ohttp(&self) -> Option<OhttpKeys> {
        get_param(self, "ohttp=", |value| OhttpKeys::from_str(value).ok())
    }

    /// Set the ohttp parameter in the URL fragment
    fn set_ohttp(&mut self, ohttp: Option<OhttpKeys>) {
        set_param(self, "ohttp=", ohttp.map(|o| o.to_string()))
    }

    /// Retrieve the exp parameter from the URL fragment
    fn exp(&self) -> Option<std::time::SystemTime> {
        get_param(self, "exp=", |value| {
            value
                .parse::<u64>()
                .ok()
                .map(|timestamp| std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp))
        })
    }

    /// Set the exp parameter in the URL fragment
    fn set_exp(&mut self, exp: Option<std::time::SystemTime>) {
        let exp_str = exp.map(|e| {
            match e.duration_since(std::time::UNIX_EPOCH) {
                Ok(duration) => duration.as_secs().to_string(),
                Err(_) => "0".to_string(), // Handle times before Unix epoch by setting to "0"
            }
        });
        set_param(self, "exp=", exp_str)
    }
}

fn get_param<F, T>(url: &Url, prefix: &str, parse: F) -> Option<T>
where
    F: Fn(&str) -> Option<T>,
{
    if let Some(fragment) = url.fragment() {
        for param in fragment.split('&') {
            if let Some(value) = param.strip_prefix(prefix) {
                return parse(value);
            }
        }
    }
    None
}

fn set_param(url: &mut Url, prefix: &str, value: Option<String>) {
    let fragment = url.fragment().unwrap_or("");
    let mut fragment = fragment.to_string();
    if let Some(start) = fragment.find(prefix) {
        let end = fragment[start..].find('&').map_or(fragment.len(), |i| start + i);
        fragment.replace_range(start..end, "");
        if fragment.ends_with('&') {
            fragment.pop();
        }
    }

    if let Some(value) = value {
        let new_param = format!("{}{}", prefix, value);
        if !fragment.is_empty() {
            fragment.push('&');
        }
        fragment.push_str(&new_param);
    }

    url.set_fragment(if fragment.is_empty() { None } else { Some(&fragment) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Uri, UriExt};

    #[test]
    fn test_ohttp_get_set() {
        let mut url = Url::parse("https://example.com").unwrap();

        let ohttp_keys =
            OhttpKeys::from_str("AQO6SMScPUqSo60A7MY6Ak2hDO0CGAxz7BLYp60syRu0gw").unwrap();
        url.set_ohttp(Some(ohttp_keys.clone()));
        assert_eq!(url.fragment(), Some("ohttp=AQO6SMScPUqSo60A7MY6Ak2hDO0CGAxz7BLYp60syRu0gw"));

        assert_eq!(url.ohttp(), Some(ohttp_keys));

        url.set_ohttp(None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_exp_get_set() {
        let mut url = Url::parse("https://example.com").unwrap();

        let exp_time =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1720547781);
        url.set_exp(Some(exp_time));
        assert_eq!(url.fragment(), Some("exp=1720547781"));

        assert_eq!(url.exp(), Some(exp_time));

        url.set_exp(None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_invalid_v2_url_fragment_on_bip21() {
        // fragment is not percent encoded so `&ohttp=` is parsed as a query parameter, not a fragment parameter
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pj=https://example.com\
                   #exp=1720547781&ohttp=AQO6SMScPUqSo60A7MY6Ak2hDO0CGAxz7BLYp60syRu0gw";
        let uri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(uri.extras.endpoint().ohttp().is_none());
    }

    #[test]
    fn test_valid_v2_url_fragment_on_bip21() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pj=https://example.com\
                   #ohttp%3DAQO6SMScPUqSo60A7MY6Ak2hDO0CGAxz7BLYp60syRu0gw";
        let uri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(uri.extras.endpoint().ohttp().is_some());
    }
}
