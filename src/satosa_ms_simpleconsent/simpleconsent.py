"""
Integrate the "simple consent" application into SATOSA

Logic:
  1. verify consent (API call)
  2. continue with response if true
  3. request consent (redirect to consent app)
  4. (consent service app will redirect to _handle_consent_response)
  5. verify consent (API call)
  6. delete attributes if no consent
  7. continue with response

"""
import base64
import hashlib
import hmac
import json
import logging
import pickle
import sys
import urllib.parse

import requests
from requests.exceptions import ConnectionError

import satosa
from satosa.internal import InternalData
from satosa.logging_util import satosa_logging
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect

logger = logging.getLogger(__name__)

RESPONSE_STATE = "Saml2IDP"
CONSENT_ID = "SimpleConsent"
CONSENT_INT_DATA = 'simpleconsent.internaldata'
VERIFY_SSL = False


class ConsentAttribute(object):
    def __init__(self, name, translation="", value=""):
        self.name = name
        self.translation = translation
        self.value = value

    def datadict(self):
        return {
            'name': self.name,
            'trans': self.translation,
            'val': self.value
        }


class ConsentGroups(object):
    def __init__(self, config):
        self.config = config
        self.groups = {}
        self.groupnames = list(self.config.keys())
        self.groupnames.append(None)
        self.groupattrs = []
        self.otherattrs= []

    def add(self, attr):
        group = self.group_of_attr(attr)
        if group:
            self.groupattrs.append(attr)
        else:
            self.otherattrs.append(attr)

    def group_of_attr(self, a):
        for gname, gattrs in self.config.items():
            if a.name in gattrs:
                return gname
        return None

    def as_struct(self):
        data = {}
        for gname, gattrs in self.config.items():
            attrs = []
            for a in self.groupattrs:
                if a.name in gattrs:
                    attrs.append(a.datadict())
            if attrs:
                data.update({gname: attrs})
        attrs = []
        for a in self.otherattrs:
            attrs.append(a.datadict())
        if attrs:
            data.update({'default': attrs})
        return data


class UnexpectedResponseError(Exception):
    pass


class SimpleConsent(ResponseMicroService):
    def __init__(self, config: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.consent_attrname_display = config['consent_attrname_display']
        self.consent_attr_not_displayed = config['consent_attr_not_displayed']
        self.consent_groups = config['consent_groups']
        self.consent_cookie_name = config['consent_cookie_name']
        self.consent_service_api_auth = config['consent_service_api_auth']
        self.endpoint = "simpleconsent_response"
        self.id_hash_alg = config['id_hash_alg']
        self.name = "simpleconsent"
        self.proxy_hmac_key = config['PROXY_HMAC_KEY'].encode('ascii')
        self.request_consent_url = config['request_consent_url']
        self.self_entityid = config['self_entityid']
        self.sp_entityid_names: dict = config['sp_entityid_names']
        self.verify_consent_url = config['verify_consent_url']
        logging.info('SimpleConsent microservice active')

    def _end_consent_flow(self, context: satosa.context.Context,
                          internal_response: satosa.internal.InternalData) -> satosa.response.Response:
        del context.state[CONSENT_ID]
        return super().process(context, internal_response)

    def _handle_consent_response(self, context: satosa.context.Context):

        logging.debug(f"SimpleConsent microservice: resuming response processing after requesting consent")
        internal_resp_ser = base64.b64decode(context.state[CONSENT_INT_DATA].encode('ascii'))
        internal_response = pickle.loads(internal_resp_ser)
        consent_id = context.state[CONSENT_ID]

        try:
            consent_given = self._verify_consent(internal_response.requester, consent_id)
        except ConnectionError:
            satosa_logging(logger, logging.ERROR,
                           "Consent service is not reachable, no consent given.", context.state)
            internal_response.attributes = {}

        if consent_given:
            satosa_logging(logger, logging.INFO, "Consent was given", context.state)
        else:
            satosa_logging(logger, logging.INFO, "Consent was NOT given, removing attributes", context.state)
            internal_response.attributes = {}

        return self._end_consent_flow(context, internal_response)

    def _get_consent_id(self, user_id: str, attr_set: dict) -> str:
        # include attributes in id_hash to ensure that consent is invalid if the attribute set changes
        attr_key_list = sorted(attr_set.keys())
        consent_id_json = json.dumps([user_id, attr_key_list])
        if self.id_hash_alg == 'md5':
            consent_id_hash = hashlib.md5(consent_id_json.encode('utf-8'))
        elif self.id_hash_alg == 'sha224':
            consent_id_hash = hashlib.sha224(consent_id_json.encode('utf-8'))
        else:
            raise Exception("Simpleconsent.config.id_hash_alg must be in ('md5', 'sha224')")
        return consent_id_hash.hexdigest()

    def process(self, context: satosa.context.Context,
                internal_resp: satosa.internal.InternalData) -> satosa.response.Response:

        response_state = context.state[RESPONSE_STATE]
        consent_id = self._get_consent_id(internal_resp.subject_id, internal_resp.attributes)
        context.state[CONSENT_ID] = consent_id
        logging.debug(f"SimpleConsent microservice: verify consent, id={consent_id}")
        try:
            # Check if consent is already given
            consent_given = self._verify_consent(internal_resp.requester, consent_id)
        except requests.exceptions.ConnectionError:
            satosa_logging(logger, logging.ERROR,
                           f"Consent service is not reachable at {self.verify_consent_url}, no consent given.",
                           context.state)
            # Send an internal_resp without any attributes
            internal_resp.attributes = {}
            return self._end_consent_flow(context, internal_resp)

        if consent_given:
            satosa_logging(logger, logging.DEBUG, "SimpleConsent microservice: previous consent found", context.state)
            return self._end_consent_flow(context, internal_resp)   # return attribute set unmodified
        else:
            logging.debug(f"SimpleConsent microservice: starting redirect to request consent")
            # save internal response
            internal_resp_ser = pickle.dumps(internal_resp)
            context.state[CONSENT_INT_DATA] = base64.b64encode(internal_resp_ser).decode('ascii')
            # create request object & redirect
            consent_requ_json = self._make_consent_request(response_state, consent_id, internal_resp.attributes)
            hmac_str = hmac.new(self.proxy_hmac_key, consent_requ_json.encode('utf-8'), hashlib.sha256).hexdigest()
            consent_requ_b64 = base64.urlsafe_b64encode(consent_requ_json.encode('ascii')).decode('ascii')
            redirecturl = f"{self.request_consent_url}/{urllib.parse.quote_plus(consent_requ_b64)}/{hmac_str}/"
            return satosa.response.Redirect(redirecturl)

        return super().process(context, internal_resp)

    def _make_consent_request(self, response_state: dict, consent_id: str, attr: list) -> dict:
        display_attr: set = set.difference(set(attr), set(self.consent_attr_not_displayed))
        for attr_name, attr_name_translated in self.consent_attrname_display.items():
            if attr_name in display_attr:
                display_attr.discard(attr_name)
                display_attr.add(attr_name_translated)

        not_filtered_attrs: set = set.difference(set(attr), set(self.consent_attr_not_displayed))
        all_attrs = ConsentGroups(self.consent_groups)
        for attr_name, attr_name_translated in self.consent_attrname_display.items():
            if attr_name in not_filtered_attrs:
                val = ','.join(attr[attr_name])
                all_attrs.add(ConsentAttribute(
                    attr_name,
                    attr_name_translated,
                    val
                ))
        consent_attributes = all_attrs.as_struct()

        try:
            displayname = attr['displayname'][0] if attr['displayname'] else ''
        except KeyError:
            displayname = ''
        try:
            mywkisurl = attr['mywkisurl'][0]
        except KeyError:
            mywkisurl = ''
        entityid = response_state['resp_args']['sp_entity_id']
        sp_name = self.sp_entityid_names.get(entityid, entityid)
        uid = attr['mail'][0] if attr['mail'] else ''

        consent_requ_dict = {
            "entityid": entityid,
            "consentid": consent_id,
            "displayname": displayname,
            "mail": uid,
            "sp": sp_name,
            "attr_list": sorted(list(display_attr)),
            "consent_attrs": consent_attributes,
            "mywkisurl": mywkisurl,
        }
        consent_requ_json = json.dumps(consent_requ_dict)
        return consent_requ_json

    def register_endpoints(self) -> list:
        return [("^{}$".format(self.endpoint), self._handle_consent_response), ]

    def _verify_consent(self, requester, consent_id: str) -> bool:
        requester_b64 = base64.urlsafe_b64encode(requester.encode('ascii')).decode('ascii')
        url = f"{self.verify_consent_url}/{requester_b64}/{consent_id}/"
        try:
            api_cred = (self.consent_service_api_auth['userid'],
                        self.consent_service_api_auth['password'])

            response = requests.request(method='GET', url=url, auth=(api_cred), verify=VERIFY_SSL)

            if response.status_code == 200:
                return json.loads(response.text)
            else:
                raise ConnectionError(f"GET {url} returned status code {response.status_code}")
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"GET {url} {str(e)}")
            raise
