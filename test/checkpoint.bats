#!/usr/bin/env bats

load helpers

function setup() {
	has_criu
	setup_test
}

function teardown() {
	cleanup_test
}

@test "checkpoint and restore one container into original pod" {
	start_crio
	pod_id=$(crictl runp "$TESTDATA"/sandbox_config.json)
	ctr_id=$(crictl create "$pod_id" "$TESTDATA"/container_redis.json "$TESTDATA"/sandbox_config.json)
	crictl start "$ctr_id"
	crictl checkpoint "$ctr_id"
	crictl restore "$ctr_id"
	crictl rmp -f "$pod_id"
}

@test "checkpoint and restore one container into a new pod" {
	start_crio
	pod_id=$(crictl runp "$TESTDATA"/sandbox_config.json)
	ctr_id=$(crictl create "$pod_id" "$TESTDATA"/container_redis.json "$TESTDATA"/sandbox_config.json)
	crictl start "$ctr_id"
	crictl checkpoint "$ctr_id"
	new_pod_id=$(crictl runp "$TESTDATA"/sandbox_config_restore.json)
	crictl restore -p "$new_pod_id" "$ctr_id"
	crictl rmp -f "$new_pod_id"
	crictl rmp -f "$pod_id"
}

@test "checkpoint and restore one container into a new pod using --export" {
	start_crio
	pod_id=$(crictl runp "$TESTDATA"/sandbox_config.json)
	ctr_id=$(crictl create "$pod_id" "$TESTDATA"/container_redis.json "$TESTDATA"/sandbox_config.json)
	crictl start "$ctr_id"
	crictl checkpoint --export="$TESTDIR"/cp.tar "$ctr_id"
	crictl rmp -f "$pod_id"
	pod_id=$(crictl runp "$TESTDATA"/sandbox_config.json)
	ctr_id=$(crictl restore -p "$pod_id" --import="$TESTDIR"/cp.tar)
	crictl rmp -f "$pod_id"
}

@test "checkpoint and restore one pod using --export" {
	start_crio
	pod_id=$(crictl runp "$TESTDATA"/sandbox_config_restore.json)
	ctr_id=$(crictl create "$pod_id" "$TESTDATA"/container_redis.json "$TESTDATA"/sandbox_config_restore.json)
	ctr_id_sleep=$(crictl create "$pod_id" "$TESTDATA"/container_sleep.json "$TESTDATA"/sandbox_config_restore.json)
	crictl start "$ctr_id"
	crictl start "$ctr_id_sleep"
	crictl checkpoint --export="$TESTDIR"/cp.tar "$pod_id"
	crictl rmp -f "$pod_id"
	pod_id=$(crictl restore --import="$TESTDIR"/cp.tar)
	crictl rmp -f "$pod_id"
}
