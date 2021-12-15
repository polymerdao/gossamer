// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ChainSafe/gossamer/dot/sync (interfaces: ChainSync)

// Package sync is a generated GoMock package.
package sync

import (
	big "math/big"
	reflect "reflect"

	types "github.com/ChainSafe/gossamer/dot/types"
	common "github.com/ChainSafe/gossamer/lib/common"
	gomock "github.com/golang/mock/gomock"
	peer "github.com/libp2p/go-libp2p-core/peer"
)

// MockChainSync is a mock of ChainSync interface.
type MockChainSync struct {
	ctrl     *gomock.Controller
	recorder *MockChainSyncMockRecorder
}

// MockChainSyncMockRecorder is the mock recorder for MockChainSync.
type MockChainSyncMockRecorder struct {
	mock *MockChainSync
}

// NewMockChainSync creates a new mock instance.
func NewMockChainSync(ctrl *gomock.Controller) *MockChainSync {
	mock := &MockChainSync{ctrl: ctrl}
	mock.recorder = &MockChainSyncMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockChainSync) EXPECT() *MockChainSyncMockRecorder {
	return m.recorder
}

// setBlockAnnounce mocks base method.
func (m *MockChainSync) setBlockAnnounce(arg0 peer.ID, arg1 *types.Header) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "setBlockAnnounce", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// setBlockAnnounce indicates an expected call of setBlockAnnounce.
func (mr *MockChainSyncMockRecorder) setBlockAnnounce(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "setBlockAnnounce", reflect.TypeOf((*MockChainSync)(nil).setBlockAnnounce), arg0, arg1)
}

// setPeerHead mocks base method.
func (m *MockChainSync) setPeerHead(arg0 peer.ID, arg1 common.Hash, arg2 *big.Int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "setPeerHead", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// setPeerHead indicates an expected call of setPeerHead.
func (mr *MockChainSyncMockRecorder) setPeerHead(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "setPeerHead", reflect.TypeOf((*MockChainSync)(nil).setPeerHead), arg0, arg1, arg2)
}

// start mocks base method.
func (m *MockChainSync) start() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "start")
}

// start indicates an expected call of start.
func (mr *MockChainSyncMockRecorder) start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "start", reflect.TypeOf((*MockChainSync)(nil).start))
}

// stop mocks base method.
func (m *MockChainSync) stop() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "stop")
}

// stop indicates an expected call of stop.
func (mr *MockChainSyncMockRecorder) stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "stop", reflect.TypeOf((*MockChainSync)(nil).stop))
}

// syncState mocks base method.
func (m *MockChainSync) syncState() chainSyncState {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "syncState")
	ret0, _ := ret[0].(chainSyncState)
	return ret0
}

// syncState indicates an expected call of syncState.
func (mr *MockChainSyncMockRecorder) syncState() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "syncState", reflect.TypeOf((*MockChainSync)(nil).syncState))
}
