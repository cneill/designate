"""
Copyright 2015 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from tempest_lib import exceptions
from six import string_types
from six.moves.urllib.parse import quote_plus


from functionaltests.common import datagen
from functionaltests.common import utils
from functionaltests.api.v2.security_utils import FuzzFactory
from functionaltests.api.v2.base import DesignateV2Test
from functionaltests.api.v2.clients.recordset_client import RecordsetClient
from functionaltests.api.v2.models.recordset_model import RecordsetModel
from functionaltests.api.v2.clients.zone_client import ZoneClient


fuzzer = FuzzFactory()


@utils.parameterized_class
class RecordsetFuzzTest(DesignateV2Test):

    def setUp(self):
        super(RecordsetFuzzTest, self).setUp()
        # self.increase_quotas(user='admin')
        resp, self.zone = ZoneClient.as_user('default').post_zone(
            datagen.random_zone_data())
        # ZoneClient.as_user('default').wait_for_zone(self.zone.id)
        self.client = RecordsetClient.as_user('default')

    def tearDown(self):
        super(RecordsetFuzzTest, self).tearDown()
        ZoneClient.as_user('default').delete_zone(self.zone.id)

    @utils.parameterized(fuzzer.get_param_datasets(
        ['accept', 'content-type'],
        ['content_types', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_fuzzed_header(self, parameter, fuzz_type, payload):
        """Create A RRSet, fuzzing Accept & Content-Type headers"""
        model = datagen.random_a_recordset(self.zone.name)
        headers = {
            'content-type': 'application/json',
            'accept': ''
        }
        headers[parameter] = payload.encode('utf-8')
        result = fuzzer.verify_tempest_exception(
            self.client.post_recordset, fuzz_type, self.zone.id, model,
            headers=headers)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_param_datasets(
        ['type', 'name', 'records', 'ttl', 'description'],
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_fuzzed_record(self, parameter, fuzz_type, payload):
        """Create A RRSet, fuzzing each param"""
        model = datagen.random_a_recordset(self.zone.name)
        model.__dict__[parameter] = payload
        result = fuzzer.verify_tempest_exception(
            self.client.post_recordset, fuzz_type, self.zone.id, model
        )
        self.assertTrue(result['status'])
        if result['exception']:
            self.assertIsInstance(result['exception'], exceptions.BadRequest)

    @utils.parameterized(fuzzer.get_param_datasets(
        ['MX', 'NS', 'AAAA', 'CNAME', 'TXT', 'SSHFP', 'SPF', 'SRV', 'PTR'],
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_fuzzed_record(self, parameter, fuzz_type, payload):
        """Create each RRSet type with fuzzed 'records' param"""
        model = RecordsetModel.from_dict({
            'type': parameter,
            'name': self.zone.name,
            'records': [payload],
            'ttl': 1500})
        result = fuzzer.verify_tempest_exception(
            self.client.post_recordset, fuzz_type, self.zone.id, model
        )
        self.assertTrue(result['status'])
        if result['exception']:
            self.assertIsInstance(result['exception'], exceptions.BadRequest)

    @utils.parameterized(fuzzer.get_datasets(
        ['number', 'junk', 'sqli', 'xss', 'rce', 'url']
    ))
    def test_get_record_fuzzed_id(self, fuzz_type, payload):
        """Get non-existant RRSet with fuzz payload as RRSet ID"""
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        result = fuzzer.verify_tempest_exception(
            self.client.get_recordset, fuzz_type, self.zone.id,
            payload
        )
        self.assertTrue(result['status'])
        if result['exception']:
            try:
                self.assertIsInstance(result['exception'], exceptions.NotFound)
            except:
                self.assertIsInstance(
                    result['exception'], exceptions.BadRequest)

    @utils.parameterized(fuzzer.get_param_datasets(
        ['limit', 'marker', 'sort_key', 'sort_dir', 'type', 'name', 'ttl',
            'data', 'description', 'status'],
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_get_records_fuzzed(self, parameter, fuzz_type, payload):
        """Get RRSet list, fuzzing each filter param"""
        model = datagen.random_a_recordset(self.zone.name)
        resp, post_resp_model = self.client.post_recordset(self.zone.id, model)
        result = fuzzer.verify_tempest_exception(
            self.client.list_recordsets, fuzz_type, self.zone.id,
            filters={parameter: payload}
        )
        self.assertTrue(result['status'])
        if result['exception']:
            self.assertIsInstance(result['exception'], exceptions.BadRequest)

    @utils.parameterized(fuzzer.get_param_datasets(
        ['type', 'name', 'records', 'ttl', 'description'],
        ['junk', 'sqli', 'xss', 'rce', 'huge']
    ))
    def test_update_fuzzed_record(self, parameter, fuzz_type, payload):
        """Update a RecordSet, fuzzing each param"""
        model = datagen.random_a_recordset(self.zone.name)
        resp, post_resp_model = self.client.post_recordset(self.zone.id, model)
        recordset_id = post_resp_model.id
        model.__dict__[parameter] = payload

        result = fuzzer.verify_tempest_exception(
            self.client.put_recordset, fuzz_type, self.zone.id, recordset_id,
            model
        )
        self.assertTrue(result['status'])
        if result['exception']:
            self.assertIsInstance(result['exception'], exceptions.BadRequest)

    @utils.parameterized(fuzzer.get_datasets(
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_delete_records_fuzzed_id(self, fuzz_type, payload):
        """Delete non-existant RRSet with fuzz payload as RRSet ID"""
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        result = fuzzer.verify_tempest_exception(
            self.client.delete_recordset, fuzz_type, self.zone.id,
            payload
        )
        self.assertTrue(result['status'])
        if result['exception']:
            try:
                self.assertIsInstance(result['exception'], exceptions.NotFound)
            except:
                self.assertIsInstance(
                    result['exception'], exceptions.BadRequest)
