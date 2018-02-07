# (C) Datadog, Inc. 2016-2017
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

# stdlib
import calendar
import logging
import re
import time
from collections import defaultdict
from urlparse import urljoin

# 3p
import requests
import simplejson as json

# project
from checks import AgentCheck, CheckException
from checks.prometheus_check import PrometheusCheck
from config import _is_affirmative
from utils.service_discovery.sd_backend import get_sd_backend
# TODO: support Agent 5
# try:
#     from kubeutil import get_connection_info
# except ImportError:
from utils.kubernetes.kubeutil import get_connection_info
from tagger import get_tags

METRIC_TYPES = ['counter', 'gauge', 'summary']
# container-specific metrics should have all these labels
CONTAINER_LABELS = ['container_name', 'namespace', 'pod_name', 'name', 'image', 'id']

DEFAULT_LABEL_PREFIX = 'kube_'
DEFAULT_TLS_VERIFY = True
KUBELET_HEALTH_PATH = '/healthz'
MACHINE_INFO_PATH = '/spec'
POD_LIST_PATH = '/pods/'

# Suffixes per
# https://github.com/kubernetes/kubernetes/blob/8fd414537b5143ab039cb910590237cabf4af783/pkg/api/resource/suffix.go#L108
FACTORS = {
    'n': float(1)/(1000*1000*1000),
    'u': float(1)/(1000*1000),
    'm': float(1)/1000,
    'k': 1000,
    'M': 1000*1000,
    'G': 1000*1000*1000,
    'T': 1000*1000*1000*1000,
    'P': 1000*1000*1000*1000*1000,
    'E': 1000*1000*1000*1000*1000*1000,
    'Ki': 1024,
    'Mi': 1024*1024,
    'Gi': 1024*1024*1024,
    'Ti': 1024*1024*1024*1024,
    'Pi': 1024*1024*1024*1024*1024,
    'Ei': 1024*1024*1024*1024*1024*1024,
}

log = logging.getLogger('collector')


class KubeletCheck(PrometheusCheck):
    """
    Collect container metrics from Kubelet.
    Custom container metrics are not supported anymore as kubelet in Kubernetes 1.6+
    switched to the CRI implementation which does not expose custom metrics.
    """

    def __init__(self, name, init_config, agentConfig, instances=None):
        super(KubeletCheck, self).__init__(name, init_config, agentConfig, instances)
        self.NAMESPACE = 'kubelet'

        if instances is not None and len(instances) > 1:
            raise Exception('Kubelet check only supports one configured instance.')
        inst = instances[0] if instances else None

        self.kubelet_conn_info = get_connection_info()
        if not self.kubelet_conn_info.get('url'):
            raise Exception("Couldn't determine the kubelet URL, kubelet check won't proceed.")

        self.kube_node_labels = inst.get('node_labels_to_host_tags', {})
        self.pod_list_url = urljoin(self.kubelet_conn_info['url'], POD_LIST_PATH)
        self.kube_health_url = urljoin(self.kubelet_api_url, KUBELET_HEALTH_PATH)
        self.machine_info_url = urljoin(self.kubelet_api_url, MACHINE_INFO_PATH)

        self.metrics_mapper = {
            'kubelet_runtime_operations_errors': 'kubelet.runtime.errors',
        }
        self.ignore_metrics = [
            'container_cpu_cfs_periods_total',
            'container_cpu_cfs_throttled_periods_total',
            'container_cpu_cfs_throttled_seconds_total',
            'container_cpu_load_average_10s',
            'container_cpu_system_seconds_total',
            'container_cpu_user_seconds_total',
            'container_fs_inodes_free',
            'container_fs_inodes_total',
            'container_fs_io_current',
            'container_fs_io_time_seconds_total',
            'container_fs_io_time_weighted_seconds_total',
            'container_fs_read_seconds_total',
            'container_fs_reads_merged_total',
            'container_fs_reads_total',
            'container_fs_sector_reads_total',
            'container_fs_sector_writes_total',
            'container_fs_write_seconds_total',
            'container_fs_writes_merged_total',
            'container_fs_writes_total',
            'container_last_seen',
            'container_start_time_seconds',
            'container_spec_memory_swap_limit_bytes',
            'container_scrape_error'
        ]

        # these are filled by container_<metric-name>_usage_<metric-unit>
        # and container_<metric-name>_limit_<metric-unit> reads it to compute <metric-name>usage_pct
        self.fs_usage_bytes = {}
        self.mem_usage_bytes = {}

    def check(self, instance):
        endpoint = instance.get('metrics_endpoint')
        if endpoint is None:
            raise CheckException("Unable to find metrics_endpoint in config file.")

        send_buckets = instance.get('send_histograms_buckets', True)
        # By default we send the buckets.
        if send_buckets is not None and str(send_buckets).lower() == 'false':
            send_buckets = False
        else:
            send_buckets = True

        try:
            pod_list = self.retrieve_pod_list()
        except Exception:
            pod_list = None

        instance_tags = instance.get('tags', [])
        self._report_node_metrics(instance_tags)
        self._perform_kubelet_check(instance_tags)
        self._report_pods_running(pod_list, instance_tags)
        self._report_container_spec_metrics(pod_list, instance_tags)
        self.process(endpoint, send_histograms_buckets=send_buckets, instance=instance)

    def perform_kubelet_query(self, url, verbose=True, timeout=10):
        """
        Perform and return a GET request against kubelet. Support auth and TLS validation.
        """
        headers = None
        cert = (self.kubelet_conn_info.get('client_crt'), self.kubelet_conn_info.get('client_key'))
        if not cert[0] or not cert[1]:
            cert = None

        verify = self.kubelet_conn_info.get('ca_cert') or self.kubelet_conn_info['verify_tls']

        # if cert-based auth is enabled, don't use the token.
        if not cert and url.lower().startswith('https') and 'token' in self.kubelet_conn_info:
            headers = {'Authorization': 'Bearer {}'.format(self.kubelet_conn_info['token'])}

        return requests.get(url, timeout=timeout, verify=verify,
                            cert=cert, headers=headers, params={'verbose': verbose})

    def retrieve_pod_list(self):
        return self.perform_kubelet_query(self.pod_list_url).json()

    def retrieve_machine_info(self):
        """
        Retrieve machine info from kubelet.
        """
        machine_info = self.perform_kubelet_query(self.machine_info_url).json()
        # TODO: replace with something node local, or using the DCA
        # try:
        #     _, node_name = self.get_node_info()
        #     request_url = "%s/nodes/%s" % (self.kubernetes_api_url, node_name)
        #     node_status = self.retrieve_json_auth(request_url).json()['status']
        #     machine_info['pods'] = node_status.get('capacity', {}).get('pods')
        #     machine_info['allocatable'] = node_status.get('allocatable', {})
        # except Exception as ex:
        #     log.debug("Failed to get node info from the apiserver: %s" % str(ex))
        return machine_info

    def _report_node_metrics(self, instance_tags):
        # TODO: find if we can report pod capacity and allocatable resources locally.
        # TODO: find if /spec can report in json, right now this doesn't work
        machine_info = self.retrieve_machine_info()
        num_cores = machine_info.get('num_cores', 0)
        memory_capacity = machine_info.get('memory_capacity', 0)
        pod_capacity = machine_info.get('pods')

        tags = instance_tags
        self.gauge(self, self.NAMESPACE + '.cpu.capacity', float(num_cores), tags)
        self.gauge(self, self.NAMESPACE + '.memory.capacity', float(memory_capacity), tags)
        if pod_capacity:
            self.gauge(self, self.NAMESPACE + '.pods.capacity', float(pod_capacity), tags)

        # extracted from the apiserver, may be missing
        # TODO: find a local source for this - or use the DCA
        # for res, val in machine_info.get('allocatable', {}).iteritems():
        #     try:
        #         m_name = self.NAMESPACE + '.{}.allocatable'.format(res)
        #         if res == 'memory':
        #             val = self.kubeutil.parse_quantity(val)
        #         self.gauge(self, m_name, float(val), tags)
        #     except Exception as ex:
        #         self.log.warning("Failed to report metric %s. Err: %s" % (m_name, str(ex)))

    def _perform_kubelet_check(self, instance_tags):
        """Runs local service checks"""
        service_check_base = self.NAMESPACE + '.kubelet.check'
        is_ok = True
        url = self.kube_health_url

        try:
            req = self.perform_kubelet_query(url)
            for line in req.iter_lines():
                # avoid noise; this check is expected to fail since we override the container hostname
                if line.find('hostname') != -1:
                    continue

                matches = re.match(r'\[(.)\]([^\s]+) (.*)?', line)
                if not matches or len(matches.groups()) < 2:
                    continue

                service_check_name = service_check_base + '.' + matches.group(2)
                status = matches.group(1)
                if status == '+':
                    self.service_check(service_check_name, AgentCheck.OK, tags=instance_tags)
                else:
                    self.service_check(service_check_name, AgentCheck.CRITICAL, tags=instance_tags)
                    is_ok = False

        except Exception as e:
            self.log.warning('kubelet check %s failed: %s' % (url, str(e)))
            self.service_check(service_check_base, AgentCheck.CRITICAL,
                               message='Kubelet check %s failed: %s' % (url, str(e)), tags=instance_tags)
        else:
            if is_ok:
                self.service_check(service_check_base, AgentCheck.OK, tags=instance_tags)
            else:
                self.service_check(service_check_base, AgentCheck.CRITICAL, tags=instance_tags)

    def _report_pods_running(self, pods, instance_tags):
        """
        Reports the number of running pods on this node
        tagged by service and creator.
        """
        for pod in pods['items']:
            pod_id = pod.get('metadata', {}).get('ID')
            tags = get_tags(pod_id) or None
            if not tags:
                continue
            self.gauge(self, self.NAMESPACE + '.pods.running', 1, tags)

    def _report_container_spec_metrics(self, pod_list, instance_tags):
        """Reports pod requests & limits by looking at pod specs."""
        for pod in pod_list['items']:
            pod_meta = pod.get('metadata', {})
            _, pod_name = pod_meta.get('namespace'), pod_meta.get('name')

            if not pod_name:
                continue

            for ctr in pod['spec']['containers']:
                if not ctr.get('resources'):
                    continue

                c_name = ctr.get('name', '')
                tags = get_tags('docker://%s' % ctr['id'])

                try:
                    for resource, value_str in ctr.get('resources', {}).get('requests', {}).iteritems():
                        value = self.parse_quantity(value_str)
                        self.gauge(self, '{}.{}.requests'.format(self.NAMESPACE, resource), value, tags)
                except (KeyError, AttributeError) as e:
                    self.log.debug("Unable to retrieve container requests for %s: %s", c_name, e)

                try:
                    for resource, value_str in ctr.get('resources', {}).get('limits', {}).iteritems():
                        value = self.parse_quantity(value_str)
                        self.gauge(self, '{}.{}.limits'.format(self.NAMESPACE, resource), value, tags)
                except (KeyError, AttributeError) as e:
                    self.log.debug("Unable to retrieve container limits for %s: %s", c_name, e)

    @staticmethod
    def parse_quantity(s):
        number = ''
        unit = ''
        for c in s:
            if c.isdigit() or c == '.':
                number += c
            else:
                unit += c
        return float(number) * FACTORS.get(unit, 1)

    def _is_pod_metric(self, metric):
        """
        Return whether a metric is about a pod or not.
        It can be about containers, pods, or higher levels in the cgroup hierarchy
        and we don't want to report on that.
        """
        for ml in metric.label:
            if ml.name == 'container_name' and ml.value == 'POD':
                return True
            # container_cpu_usage_seconds_total has an id label that is a cgroup path
            # eg: /kubepods/burstable/pod531c80d9-9fc4-11e7-ba8b-42010af002bb
            # FIXME: this was needed because of a bug:
            # https://github.com/kubernetes/kubernetes/pull/51473
            # starting from k8s 1.8 we can remove this
            elif ml.name == 'id' and ml.value.split('/')[-1].startswith('pod'):
                return True
        return False

    def _is_container_metric(self, metric):
        """
        Return whether a metric is about a container or not.
        It can be about pods, or even higher levels in the cgroup hierarchy
        and we don't want to report on that.
        """
        for l in CONTAINER_LABELS:
            if l == 'container_name':
                for ml in metric.label:
                    if ml.name == l:
                        if ml.value == 'POD':
                            return False
            elif l not in [ml.name for ml in metric.label]:
                return False
        return True

    def _get_container_id(self, labels):
        for label in labels:
            if label.name == 'id':
                return label.value
        return None

    def container_cpu_usage_seconds_total(self, message, **kwargs):
        # TODO: this is now a pod metric, need a new pod uid --> pod name index
        metric_name = self.NAMESPACE + '.cpu.usage.total'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_container_metric(metric):
                c_id = self._get_container_id(metric.label)
                tags = get_tags('docker://%s' % c_id)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.rate(self, metric_name, val, tags)

    def _process_usage_metric(self, m_name, message, cache):
        """
        Takes a metrics message, a metric name, and a cache dict where it will store
        container_name --> (value, tags) so that _process_limit_metric can compute usage_pct
        it also submit said value and tags as a gauge.
        """
        # track containers that still exist in the cache
        seen_keys = {k: False for k in cache}
        for metric in message.metric:
            if self._is_container_metric(metric):
                c_id = self._get_container_id(metric.label)
                tags = get_tags('docker://%s' % c_id)
                c_name = None
                for t in tags:
                    if t.split(':', 1)[0] == 'container_name':
                        c_name = t.split(':', 1)[1]
                        break
                val = getattr(metric, METRIC_TYPES[message.type]).value
                if c_name:
                    cache[c_name] = (val, tags)
                    seen_keys[c_name] = True
                self.gauge(self, m_name, val, tags)

        # purge the cache
        for k, seen in seen_keys.iteritems():
            if not seen:
                del cache[k]

    def _process_limit_metric(self, m_name, message, cache, pct_m_name=None):
        """
        Reports limit metrics if m_name is not an empty string,
        and optionally checks in the given cache if there's a usage
        for each metric in the message and reports the usage_pct
        """
        for metric in message.metric:
            if self._is_container_metric(metric):
                limit = getattr(metric, METRIC_TYPES[message.type]).value
                c_id = self._get_container_id(metric.label)
                tags = get_tags('docker://%s' % c_id)

                if m_name:
                    self.gauge(self, m_name, limit, tags)

                if pct_m_name and limit > 0:
                    usage = None
                    c_name = ''
                    for lbl in metric.label:
                        if lbl.name == 'name':
                            c_name = lbl.value
                            usage, tags = cache.get(c_name, (None, None))
                            break
                    if usage:
                        self.gauge(self, pct_m_name, float(usage/float(limit)), tags)
                    else:
                        self.log.debug("No corresponding usage found for metric %s and "
                                       "container %s, skipping usage_pct for now." % (pct_m_name, c_name))

    def container_fs_usage_bytes(self, message, **kwargs):
        """
        Number of bytes that are consumed by the container on this filesystem.
        TODO: container_fs_reads_bytes_total and writes
        """
        metric_name = self.NAMESPACE + '.filesystem.usage'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return
        self._process_usage_metric(metric_name, message, self.fs_usage_bytes)

    def container_fs_limit_bytes(self, message, **kwargs):
        """
        Number of bytes that can be consumed by the container on this filesystem.
        This method is used by container_fs_usage_bytes, it doesn't report any metric
        """
        pct_m_name = self.NAMESPACE + '.filesystem.usage_pct'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return
        self._process_limit_metric('', message, self.fs_usage_bytes, pct_m_name)

    def container_memory_usage_bytes(self, message, **kwargs):
        """TODO: add swap, cache, failcnt and rss"""
        metric_name = self.NAMESPACE + '.memory.usage'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return
        self._process_usage_metric(metric_name, message, self.mem_usage_bytes)

    def container_spec_memory_limit_bytes(self, message, **kwargs):
        """TODO: compare with pod spec metrics and kill if redundant"""
        metric_name = self.NAMESPACE + '.memory.limits'
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_container_metric(metric):
                usage = None
                c_name = ''
                for lbl in metric.label:
                    if lbl.name == 'name':
                        c_name = lbl.value
                        usage, tags = self.mem_usage_bytes.get(c_name, (None, None))

                if usage and tags:
                    limit = getattr(metric, METRIC_TYPES[message.type]).value
                    if limit > 0:
                        self.gauge(self, metric_name, float(usage/float(limit)), tags)
                else:
                    self.log.debug("No mem usage found for container %s, skipping usage_pct for now." % c_name)

    def _process_pod_rate(self, metric_name, message):
        """Takes a simple metric about a pod, reports it as a rate."""
        if message.type >= len(METRIC_TYPES):
            self.log.error("Metric type %s unsupported for metric %s" % (message.type, message.name))
            return

        for metric in message.metric:
            if self._is_pod_metric(metric):
                c_id = self._get_container_id(metric.label)
                tags = get_tags('docker://%s' % c_id)
                val = getattr(metric, METRIC_TYPES[message.type]).value
                self.rate(self, metric_name, val, tags)

    def container_network_receive_bytes_total(self, message, **kwargs):
        """TODO: refactor this and the following 5 metrics"""
        metric_name = self.NAMESPACE + '.network.rx_bytes'
        self._process_pod_rate(metric_name, message)

    def container_network_transmit_bytes_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.tx_bytes'
        self._process_pod_rate(metric_name, message)

    def container_network_receive_errors_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.rx_errors'
        self._process_pod_rate(metric_name, message)

    def container_network_transmit_errors_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.tx_errors'
        self._process_pod_rate(metric_name, message)

    def container_network_transmit_packets_dropped_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.tx_dropped'
        self._process_pod_rate(metric_name, message)

    def container_network_receive_packets_dropped_total(self, message, **kwargs):
        metric_name = self.NAMESPACE + '.network.rx_dropped'
        self._process_pod_rate(metric_name, message)
