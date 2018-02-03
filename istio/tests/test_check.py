# (C) Datadog, Inc. 2010-2017
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

# stdlib
import mock
import os

# 3rd-party
import pytest

# project
from datadog_checks.istio import Istio



MESH_METRICS = ['istio.mesh.request.count',
                'istio.mesh.request.duration.count',
                'istio.mesh.request.duration.sum',
                'istio.mesh.request.size.count',
                'istio.mesh.request.size.sum',
                'istio.mesh.response.size.count',
                'istio.mesh.response.size.sum']

MIXER_METRICS = ['istio.mixer.adapter.dispatch_duration.count',
                'istio.mixer.adapter.dispatch_duration.sum',
                'istio.mixer.go.gc_duration_seconds.count',
                'istio.mixer.go.gc_duration_seconds.quantile',
                'istio.mixer.go.gc_duration_seconds.sum',
                'istio.mixer.go.goroutines',
                'istio.mixer.go.info',
                'istio.mixer.go.memstats.alloc_bytes',
                'istio.mixer.go.memstats.alloc_bytes_total',
                'istio.mixer.go.memstats.buck_hash_sys_bytes',
                'istio.mixer.go.memstats.frees_total',
                'istio.mixer.go.memstats.gc_cpu_fraction',
                'istio.mixer.go.memstats.gc_sys_bytes',
                'istio.mixer.go.memstats.heap_alloc_bytes',
                'istio.mixer.go.memstats.heap_idle_bytes',
                'istio.mixer.go.memstats.heap_inuse_bytes',
                'istio.mixer.go.memstats.heap_objects',
                'istio.mixer.go.memstats.heap_released_bytes',
                'istio.mixer.go.memstats.heap_sys_bytes',
                'istio.mixer.go.memstats.last_gc_time_seconds',
                'istio.mixer.go.memstats.lookups_total',
                'istio.mixer.go.memstats.mallocs_total',
                'istio.mixer.go.memstats.mcache_inuse_bytes',
                'istio.mixer.go.memstats.mcache_sys_bytes',
                'istio.mixer.go.memstats.mspan_inuse_bytes',
                'istio.mixer.go.memstats.mspan_sys_bytes',
                'istio.mixer.go.memstats.next_gc_bytes',
                'istio.mixer.go.memstats.other_sys_bytes',
                'istio.mixer.go.memstats.stack_inuse_bytes',
                'istio.mixer.go.memstats.stack_sys_bytes',
                'istio.mixer.go.memstats.sys_bytes',
                'istio.mixer.go.threads',
                'istio.mixer.grpc.server.handled_total',
                'istio.mixer.grpc.server.handling_seconds.count',
                'istio.mixer.grpc.server.handling_seconds.sum',
                'istio.mixer.grpc.server.msg_received_total',
                'istio.mixer.grpc.server.msg_sent_total',
                'istio.mixer.grpc.server.started_total',
                'istio.mixer.adapter.dispatch_count',
                'istio.mixer.adapter.old_dispatch_count',
                'istio.mixer.adapter.old_dispatch_duration.count',
                'istio.mixer.adapter.old_dispatch_duration.sum',
                'istio.mixer.config.resolve_actions.count',
                'istio.mixer.config.resolve_actions.sum',
                'istio.mixer.config.resolve_count',
                'istio.mixer.config.resolve_duration.count',
                'istio.mixer.config.resolve_duration.sum',
                'istio.mixer.config.resolve_rules.count',
                'istio.mixer.config.resolve_rules.sum',
                'istio.mixer.process.cpu_seconds_total',
                'istio.mixer.process.max_fds',
                'istio.mixer.process.open_fds',
                'istio.mixer.process.resident_memory_bytes',
                'istio.mixer.process.start_time_seconds',
                'istio.mixer.process.virtual_memory_bytes']

class MockResponse:
    """
    MockResponse is used to simulate the object requests.Response commonly returned by requests.get
    """

    def __init__(self, content, content_type):
        if isinstance(content, list):
            self.content = content
        else:
            self.content = [content]
        self.headers = {'Content-Type': content_type}

    def iter_lines(self, **_):
        content = self.content.pop(0)
        for elt in content.split("\n"):
            yield elt

    def close(self):
        pass


@pytest.fixture
def aggregator():
    from datadog_checks.stubs import aggregator
    aggregator.reset()
    return aggregator

@pytest.fixture
def mock_poll():
    from checks.prometheus_check import PrometheusCheck
    mesh_file_path = os.path.join(os.path.dirname(__file__), 'ci', 'fixtures', 'istio', 'mesh.txt')
    mixer_file_path = os.path.join(os.path.dirname(__file__), 'ci', 'fixtures', 'istio', 'mixer.txt')
    responses = []
    with open(mesh_file_path, 'rb') as f:
        responses.append(f.read())
    with open(mixer_file_path, 'rb') as f:
        responses.append(f.read())

@mock.patch('checks.prometheus_check.PrometheusCheck.poll')
def test_istio(aggregator):
    mesh_file_path = os.path.join(os.path.dirname(__file__), 'ci', 'fixtures', 'istio', 'mesh.txt')
    mixer_file_path = os.path.join(os.path.dirname(__file__), 'ci', 'fixtures', 'istio', 'mixer.txt')
    responses = []
    with open(mesh_file_path, 'rb') as f:
        responses.append(f.read())
    with open(mixer_file_path, 'rb') as f:
        responses.append(f.read())
    mock_poll.return_value = MockResponse(responses, 'text/plain')

    instance = {
        'istio_mesh_endpoint': 'http://localhost:42422/metrics',
        'mixer_endpoint': 'http://localhost:9093/metrics'
    }

    c = Istio('istio', None, {}, [instance])
    c.check(instance)

    metrics = MESH_METRICS + MIXER_METRICS
    for metric in metrics:
        aggregator.assert_metric(metric)

    assert aggregator.metrics_asserted_pct == 100.0
