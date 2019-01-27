"""Tests for certbot_dns_aliyun.dns_aliyun."""

import os
import unittest


from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
import mock

from certbot import errors
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

ACCESS_KEY_ID = 'my-access-key'
ACCESS_KEY_SECRET = 'my-access-secret'


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_aliyun.dns_aliyun import Authenticator

        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"access-key-id": ACCESS_KEY_ID, "access-key-secret": ACCESS_KEY_SECRET}, path)

        self.config = mock.MagicMock(aliyun_credentials=path,
                                     aliyun_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "aliyun")

        self.mock_client = mock.MagicMock()
        # _get_aliyun_client | pylint: disable=protected-access
        self.auth._get_aliyun_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class AliyunClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"
    record_ttl = 42
    zone_id = 1
    record_id = 2

    def setUp(self):
        from certbot_dns_aliyun.dns_aliyun import _AliyunClient

        self.aliyun_client = _AliyunClient(ACCESS_KEY_ID, ACCESS_KEY_SECRET)

        self.cf = mock.MagicMock()
        self.aliyun_client.cf = self.cf

    def test_add_txt_record(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]

        self.aliyun_client.add_txt_record(DOMAIN, self.record_name, self.record_content,
                                              self.record_ttl)

        self.cf.zones.dns_records.post.assert_called_with(self.zone_id, data=mock.ANY)

        post_data = self.cf.zones.dns_records.post.call_args[1]['data']

        self.assertEqual('TXT', post_data['type'])
        self.assertEqual(self.record_name, post_data['name'])
        self.assertEqual(self.record_content, post_data['content'])
        self.assertEqual(self.record_ttl, post_data['ttl'])

    def test_add_txt_record_error(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]

        self.cf.zones.dns_records.post.side_effect = API_ERROR

        self.assertRaises(
            errors.PluginError,
            self.aliyun_client.add_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_error_during_zone_lookup(self):
        self.cf.zones.get.side_effect = API_ERROR

        self.assertRaises(
            errors.PluginError,
            self.aliyun_client.add_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_add_txt_record_zone_not_found(self):
        self.cf.zones.get.return_value = []

        self.assertRaises(
            errors.PluginError,
            self.aliyun_client.add_txt_record,
            DOMAIN, self.record_name, self.record_content, self.record_ttl)

    def test_del_txt_record(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.return_value = [{'id': self.record_id}]

        self.aliyun_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY),
                    mock.call.zones.dns_records.delete(self.zone_id, self.record_id)]

        self.assertEqual(expected, self.cf.mock_calls)

        get_data = self.cf.zones.dns_records.get.call_args[1]['params']

        self.assertEqual('TXT', get_data['type'])
        self.assertEqual(self.record_name, get_data['name'])
        self.assertEqual(self.record_content, get_data['content'])

    def test_del_txt_record_error_during_zone_lookup(self):
        self.cf.zones.get.side_effect = API_ERROR

        self.aliyun_client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_during_delete(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.return_value = [{'id': self.record_id}]
        self.cf.zones.dns_records.delete.side_effect = API_ERROR

        self.aliyun_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY),
                    mock.call.zones.dns_records.delete(self.zone_id, self.record_id)]

        self.assertEqual(expected, self.cf.mock_calls)

    def test_del_txt_record_error_during_get(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.side_effect = API_ERROR

        self.aliyun_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY)]

        self.assertEqual(expected, self.cf.mock_calls)

    def test_del_txt_record_no_record(self):
        self.cf.zones.get.return_value = [{'id': self.zone_id}]
        self.cf.zones.dns_records.get.return_value = []

        self.aliyun_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY),
                    mock.call.zones.dns_records.get(self.zone_id, params=mock.ANY)]

        self.assertEqual(expected, self.cf.mock_calls)

    def test_del_txt_record_no_zone(self):
        self.cf.zones.get.return_value = [{'id': None}]

        self.aliyun_client.del_txt_record(DOMAIN, self.record_name, self.record_content)
        expected = [mock.call.zones.get(params=mock.ANY)]

        self.assertEqual(expected, self.cf.mock_calls)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
