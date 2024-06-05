// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kube provides a client to interact with Kubernetes.
// This package is Tailscale-internal and not meant for external consumption.
// Further, the API should not be considered stable.
package kube

// KubernetesCapRule is a rule provided via PeerCapabilityKubernetes capability.
type KubernetesCapRule struct {
	// Impersonate is a list of rules that specify how to impersonate the caller
	// when proxying to the Kubernetes API.
	Impersonate *ImpersonateRule `json:"impersonate,omitempty"`
	// EnforceRecorder defines whether a kubectl exec session from a client
	// matching `src` to an API server proxy matching `dst` should fail
	// closed if it cannot be recorded (i.e if no recoder can be reached).
	// Default is to fail open.
	// The field name matches `EnforceRecorder` field with equal semantics for Tailscale SSH
	// session recorder.
	// https://tailscale.com/kb/1246/tailscale-ssh-session-recording#turn-on-session-recording-in-acls
	EnforceRecorder bool `json:"enforceRecorder,omitempty"`
	// Recorders defines a tag that should resolve to a tsrecorder
	// instance(s). If set, any `kubectl exec` session from a client
	// matching `src` of this grant to an API server proxy matching `dst` of
	// this grant will be recorded and the recording will be sent to the
	// tsrecorder.
	// This list must not contain more than one tag.
	// The field name matches the `Recorder` field with equal semantics for Tailscale SSH
	// session recorder.
	// https://tailscale.com/kb/1246/tailscale-ssh-session-recording#turn-on-session-recording-in-acls
	Recorders []string `json:"recorder,omitempty"`
}

// ImpersonateRule defines how a request from the tailnet identity matching
// 'src' of this grant should be impersonated.
type ImpersonateRule struct {
	// Groups can be used to set a list of groups that a request to
	// Kubernetes API server should be impersonated as from. Groups in
	// Kubernetes only exist as subjects that RBAC rules refer to. Caller
	// can choose to use an existing group, such as system:masters, or
	// create RBAC for a new group.
	// https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-subjects
	Groups []string `json:"groups,omitempty"`
}
