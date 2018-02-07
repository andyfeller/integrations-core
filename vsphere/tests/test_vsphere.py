# (C) Datadog, Inc. 2010-2017
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)
from __future__ import unicode_literals

import pytest
from mock import MagicMock

from datadog_checks.vsphere import VSphereCheck
from datadog_checks.vsphere.vsphere import MORLIST, INTERVAL, METRICS_METADATA
from .utils import create_topology, assertMOR
from .utils import MockedContainer, MockedMOR


def test_init():
    with pytest.raises(Exception):
        # Must define a unique 'name' per vCenter instance
        VSphereCheck('vsphere', {}, {}, [{'': ''}])

    init_config = {
        'refresh_morlist_interval': -99,
        'refresh_metrics_metadata_interval': -99,
    }
    check = VSphereCheck('disk', init_config, {}, [{'name': 'vsphere_foo'}])
    assert check.time_started > 0
    assert check.pool_started is False
    assert len(check.server_instances) == 0
    assert len(check.cache_times) == 1
    assert 'vsphere_foo' in check.cache_times
    assert check.cache_times['vsphere_foo'][MORLIST][INTERVAL] == -99
    assert check.cache_times['vsphere_foo'][METRICS_METADATA][INTERVAL] == -99
    assert len(check.event_config) == 1
    assert 'vsphere_foo' in check.event_config
    assert len(check.registry) == 0
    assert len(check.morlist_raw) == 0
    assert len(check.morlist) == 0
    assert len(check.metrics_metadata) == 0
    assert len(check.latest_event_query) == 0


def test__is_excluded():
    """
     * Exclude hosts/vms not compliant with the user's `*_include` configuration.
     * Exclude "non-labeled" virtual machines when the user configuration instructs to.
    """
    # Sample(s)
    include_regexes = {
        'host_include': "f[o]+",
        'vm_include': "f[o]+",
    }

    # OK
    included_host = MockedMOR(spec="HostSystem", name="foo")
    included_vm = MockedMOR(spec="VirtualMachine", name="foo")

    assert VSphereCheck._is_excluded(included_host, include_regexes, None) is False
    assert VSphereCheck._is_excluded(included_vm, include_regexes, None) is False

    # Not OK!
    excluded_host = MockedMOR(spec="HostSystem", name="bar")
    excluded_vm = MockedMOR(spec="VirtualMachine", name="bar")

    assert VSphereCheck._is_excluded(excluded_host, include_regexes, None) is True
    assert VSphereCheck._is_excluded(excluded_vm, include_regexes, None) is True

    # Sample(s)
    include_regexes = None
    include_only_marked = True

    # OK
    included_vm = MockedMOR(spec="VirtualMachine", name="foo", label=True)
    assert VSphereCheck._is_excluded(included_vm, include_regexes, include_only_marked) is False

    # Not OK
    included_vm = MockedMOR(spec="VirtualMachine", name="foo")
    assert VSphereCheck._is_excluded(included_vm, include_regexes, include_only_marked) is True


def test__discover_mor():
    """
    Explore the vCenter infrastructure to discover hosts, virtual machines.

    Input topology:
        ```
        rootFolder
            - datacenter1
                - compute_resource1
                    - host1                   # Filtered out
                    - host2
            - folder1
                - datacenter2
                    - compute_resource2
                        - host3
                        - vm1               # Not labeled
                        - vm2               # Filtered out
                        - vm3               # Powered off
                        - vm4
        ```
    """
    # Samples
    instance = {'name': 'vsphere_mock'}
    vcenter_topology = create_topology('vsphere_topology.json')
    tags = ["toto"]
    include_regexes = {
        'host_include': "host[2-9]",
        'vm_include': "vm[^2]",
    }
    include_only_marked = True

    # mock pyvmomi stuff
    view_mock = MockedContainer(topology=vcenter_topology)
    viewmanager_mock = MagicMock(**{'CreateContainerView.return_value': view_mock})
    content_mock = MagicMock(viewManager=viewmanager_mock)
    server_mock = MagicMock()
    server_mock.configure_mock(**{'RetrieveContent.return_value': content_mock})

    check = VSphereCheck('vsphere', {}, {}, [instance])
    check._get_server_instance = MagicMock(return_value=server_mock)
    check.pool = MagicMock(apply_async=lambda func, args: func(*args))

    # Discover hosts and virtual machines
    check._discover_mor(instance, tags, include_regexes, include_only_marked)

    # Assertions: 1 labaled+monitored VM + 2 hosts + 2 datacenters.
    assertMOR(check, instance, count=5)

    # ... on hosts
    assertMOR(check, instance, spec="host", count=2)
    tags = [
        "toto", "vsphere_folder:rootFolder", "vsphere_datacenter:datacenter1",
        "vsphere_compute:compute_resource1", "vsphere_cluster:compute_resource1",
        "vsphere_type:host"
    ]
    assertMOR(check, instance, name="host2", spec="host", tags=tags)
    tags = [
        "toto", "vsphere_folder:rootFolder", "vsphere_folder:folder1",
        "vsphere_datacenter:datacenter2", "vsphere_compute:compute_resource2",
        "vsphere_cluster:compute_resource2", "vsphere_type:host"
    ]
    assertMOR(check, instance, name="host3", spec="host", tags=tags)

    # ...on VMs
    assertMOR(check, instance, spec="vm", count=1)
    tags = [
        "toto", "vsphere_folder:folder1", "vsphere_datacenter:datacenter2",
        "vsphere_compute:compute_resource2", "vsphere_cluster:compute_resource2",
        "vsphere_host:host3", "vsphere_type:vm"
    ]
    assertMOR(check, instance, name="vm4", spec="vm", subset=True, tags=tags)
