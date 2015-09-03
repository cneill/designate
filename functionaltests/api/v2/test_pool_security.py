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
from six import string_types
from six.moves.urllib.parse import quote_plus

from functionaltests.api.v2.security_utils import FuzzFactory
from functionaltests.common import utils
from functionaltests.common import datagen
from functionaltests.api.v2.base import DesignateV2Test
from functionaltests.api.v2.clients.pool_client import PoolClient
# from functionaltests.api.v2.clients.zone_client import ZoneClient


fuzzer = FuzzFactory()


@utils.parameterized_class
class PoolFuzzTest(DesignateV2Test):

    def setUp(self):
        super(PoolFuzzTest, self).setUp()
        # self.client = PoolClient.as_user('admin')
        self.client = PoolClient.as_user('default')
        # self.increase_quotas(user='admin')
        self.pool_id = None

    def tearDown(self):
        super(PoolFuzzTest, self).tearDown()
        if self.pool_id:
            resp, body = self.client.delete_pool(self.pool_id)
            self.assertEqual(resp.status, 204)

    def _create_pool(self, pool_model, user='admin'):
        resp, model = PoolClient.as_user(user).post_pool(pool_model)
        self.assertEqual(resp.status, 201)
        self.pool_id = model.id
        return resp, model

    pool_params = [
        'name', 'description', 'tenant_id', 'provisioner', 'attributes'
    ]
    filters = [
        'limit', 'marker', 'sort_dir', 'type', 'name', 'ttl', 'data',
        'description', 'status'
    ]

    @utils.parameterized(fuzzer.get_param_datasets(
        ['accept', 'content-type'],
        ['content_types', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_pool_fuzz_header(self, parameter, fuzz_type, payload):
        test_model = datagen.random_pool_data()
        headers = {parameter: payload.encode('utf-8')}
        result = fuzzer.verify_tempest_exception(
            self.client.post_pool, fuzz_type, test_model, headers=headers)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))
        if result['resp'].status == 201:
            self.pool_id = result['model'].id

    @utils.parameterized(fuzzer.get_param_datasets(
        pool_params, ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_pool_fuzz_param(self, parameter, fuzz_type, payload):
        test_model = datagen.random_pool_data()
        test_model.__dict__[parameter] = payload
        result = fuzzer.verify_tempest_exception(
            self.client.post_pool, fuzz_type, test_model)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))
        if result['resp'].status == 201:
            self.pool_id = result['model'].id

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_pool_fuzz_data_hostname(self, fuzz_type, payload):
        test_model = datagen.random_pool_data()
        test_model.ns_records = [{"hostname": payload,
                                 "priority": x["priority"]}
                                 for x in test_model.ns_records]
        result = fuzzer.verify_tempest_exception(
            self.client.post_pool, fuzz_type, test_model)
        self.assertTrue(result['status'])
        self.assertEqual(result['resp'].status, 400)

    @utils.parameterized(fuzzer.get_datasets(
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_create_pool_fuzz_data_priority(self, fuzz_type, payload):
        test_model = datagen.random_pool_data()
        test_model.ns_records = [{"hostname": x["hostname"],
                                 "priority": payload}
                                 for x in test_model.ns_records]
        result = fuzzer.verify_tempest_exception(
            self.client.post_pool, fuzz_type, test_model)
        self.assertTrue(result['status'])
        self.assertEqual(result['resp'].status, 400)

    @utils.parameterized(fuzzer.get_param_datasets(
        ['accept', 'content-type'],
        ['content_types', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_update_pool_fuzz_header(self, parameter, fuzz_type, payload):
        resp, test_model = self._create_pool(datagen.random_pool_data())
        headers = {parameter: payload.encode('utf-8')}
        result = fuzzer.verify_tempest_exception(
            self.client.patch_pool, fuzz_type, test_model.id, test_model,
            headers=headers)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_param_datasets(
        pool_params, ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_update_pool_fuzz_param(self, parameter, fuzz_type, payload):
        resp, test_model = self._create_pool(datagen.random_pool_data())
        test_model.__dict__[parameter] = payload
        result = fuzzer.verify_tempest_exception(
            self.client.patch_pool, fuzz_type, test_model.id, test_model)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_update_pool_fuzz_data_hostname(self, fuzz_type, payload):
        resp, test_model = self._create_pool(datagen.random_pool_data())
        test_model.ns_records = [{"hostname": payload,
                                 "priority": x["priority"]}
                                 for x in test_model.ns_records]
        result = fuzzer.verify_tempest_exception(
            self.client.patch_pool, fuzz_type, test_model.id, test_model)
        self.assertTrue(result['status'])
        self.assertEqual(result['resp'].status, 400)

    @utils.parameterized(fuzzer.get_datasets(
        ['number', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_update_pool_fuzz_data_priority(self, fuzz_type, payload):
        resp, test_model = self._create_pool(datagen.random_pool_data())
        test_model.ns_records = [{"hostname": x["priority"],
                                 "priority": payload}
                                 for x in test_model.ns_records]
        result = fuzzer.verify_tempest_exception(
            self.client.patch_pool, fuzz_type, test_model.id, test_model)
        self.assertTrue(result['status'])
        self.assertEqual(result['resp'].status, 400)

    @utils.parameterized(fuzzer.get_datasets(
        ['content_types', 'junk', 'sqli', 'xss', 'rce']
    ))
    def test_get_pool_fuzz_accept_header(self, fuzz_type, payload):
        resp, test_model = self._create_pool(datagen.random_pool_data())
        headers = {"Accept": payload}
        result = fuzzer.verify_tempest_exception(
            self.client.get_pool, fuzz_type, test_model.id, headers=headers)
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))

    @utils.parameterized(fuzzer.get_datasets(
        ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_get_pool_fuzz_uuid(self, fuzz_type, payload):
        if isinstance(payload, string_types):
            payload = quote_plus(payload.encode('utf-8'))
        resp, test_model = self._create_pool(datagen.random_pool_data())
        result = fuzzer.verify_tempest_exception(
            self.client.get_pool, fuzz_type, payload)
        self.assertTrue(result['status'])
        self.assertEqual(result['resp'].status, 404)

    @utils.parameterized(fuzzer.get_param_datasets(
        filters, ['junk', 'sqli', 'xss', 'rce']
    ))
    def test_list_pools_fuzzed_filter(self, parameter, fuzz_type, payload):
        result = fuzzer.verify_tempest_exception(
            self.client.list_pools, fuzz_type, filters={parameter: payload})
        self.assertTrue(result['status'])
        self.assertNotIn(result['resp'].status, range(500, 600))
