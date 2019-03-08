"""DNS Authenticator for Aliyun."""
import logging
import json

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
import zope.interface


from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://usercenter.console.aliyun.com/#/manage/ak'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Aliyun

    This Authenticator uses the Aliyun API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Aliyun for '
                   'DNS).')
    ttl = 600

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='Aliyun credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Aliyun API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Aliyun credentials INI file',
            {
                'access-key-id': 'AccessKeyId obtained from {0}'.format(ACCOUNT_URL),
                'access-key-secret': 'AccessKeySecret of the AccessKeyId',
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_aliyun_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_aliyun_client().del_txt_record(domain, validation_name, validation)

    def _get_aliyun_client(self):
        return _AliyunClient(self.credentials.conf('access-key-id'), self.credentials.conf('access-key-secret'))


class _AliyunClient(object):
    """
    Encapsulates all communication with the Aliyun API.
    """

    def __init__(self, accessKeyId, accessSecret):        
        self.client = AcsClient(accessKeyId, accessSecret, 'default')

    def _common_request(self, apiName):
        request = CommonRequest()
        request.set_accept_format('json')
        request.set_domain('alidns.aliyuncs.com')
        request.set_method('POST')
        request.set_version('2015-01-09')
        request.set_action_name(apiName) 
        return request

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the Aliyun zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Aliyun API
        """

        try:
            request = self._common_request("GetMainDomainName")
            request.add_query_param('InputString', record_name)
            response = self.client.do_action_with_exception(request)
        except Exception as e:
            logger.error('Encountered Aliyun API Error get Domain name: %s', e)
            raise errors.PluginError('Error communicating with the Aliyun API: {0}'.format(e))

        rsp = json.loads(response, encoding='utf-8')
        domain = rsp["DomainName"]
        record_name = rsp["RR"]

        try:            
            request = self._common_request("AddDomainRecord")

            request.add_query_param('DomainName', domain)
            request.add_query_param('RR', record_name)
            request.add_query_param('Type', 'TXT')
            request.add_query_param('Value', record_content)
            request.add_query_param('TTL', record_ttl)

            response = self.client.do_action_with_exception(request)
        except Exception as e:
            logger.error('Encountered Aliyun API Error adding TXT record: %s', e)
            raise errors.PluginError('Error communicating with the Aliyun API: {0}'.format(e))

        rsp = json.loads(response, encoding='utf-8')

        if "Code" in rsp:
            err = 'Encountered Aliyun adding TXT error: {0}'.format(rsp["Message"])
            logger.debug(err)
            raise errors.PluginError(err)

        logger.debug('Successfully added TXT record with record_id: %s', rsp["RecordId"])

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the Aliyun zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        record_id = self._find_txt_record_id(domain, record_name, record_content)
        if record_id:
            try:
                request = self._common_request("DeleteDomainRecord")
                request.add_query_param('RecordId', record_id)                
                
                response = self.client.do_action_with_exception(request)

                rsp = json.loads(response, encoding='utf-8')

                if "Code" in rsp:
                    raise rsp["Message"]

                logger.debug('Successfully deleted TXT record.')
            except Exception as e:
                logger.warning('Encountered aliyun deleting TXT record: %s', e)
        else:
            logger.debug('TXT record not found; no cleanup needed.')

    def _find_txt_record_id(self, domain, record_name, record_content):
        """
        Find the record_id for a TXT record with the given name and content.

        :param str domain: The domain which contains the record.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :returns: The record_id, if found.
        :rtype: str
        """

        try:
            request = self._common_request('DescribeSubDomainRecords')

            request.add_query_param('SubDomain', record_name)
            request.add_query_param('Type', 'TXT')
            response = self.client.do_action_with_exception(request)
        except Exception as e:
            logger.debug('Encountered Aliyun getting TXT error: %s', e)
            return

        rsp = json.loads(response, encoding='utf-8')

        if "Code" in rsp:
            logger.debug('Encountered Aliyun getting TXT error: %s', rsp["Message"])
            return
        
        if len(rsp["DomainRecords"]["Record"]) > 0:
            # Cleanup is returning the system to the state we found it. If, for some reason,
            # there are multiple matching records, we only delete one because we only added one.

            return rsp["DomainRecords"]["Record"][0]["RecordId"]
        else:
            logger.debug('Unable to find TXT record.')