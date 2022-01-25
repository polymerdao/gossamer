// Copyright 2021 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package dot

import (
	"errors"
	"testing"

	"github.com/ChainSafe/gossamer/dot/core"
	"github.com/ChainSafe/gossamer/dot/digest"
	"github.com/ChainSafe/gossamer/dot/network"
	"github.com/ChainSafe/gossamer/dot/rpc"
	"github.com/ChainSafe/gossamer/dot/rpc/modules"
	"github.com/ChainSafe/gossamer/dot/state"
	"github.com/ChainSafe/gossamer/dot/sync"
	"github.com/ChainSafe/gossamer/dot/system"
	"github.com/ChainSafe/gossamer/dot/telemetry"
	"github.com/ChainSafe/gossamer/dot/types"
	"github.com/ChainSafe/gossamer/internal/log"
	"github.com/ChainSafe/gossamer/lib/babe"
	"github.com/ChainSafe/gossamer/lib/crypto"
	"github.com/ChainSafe/gossamer/lib/grandpa"
	"github.com/ChainSafe/gossamer/lib/keystore"
	"github.com/ChainSafe/gossamer/lib/runtime"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_createBABEService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	t.Parallel()

	cfg := NewTestConfig(t)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Core.Roles = types.FullNodeRole
	cfg.Init.Genesis = genFile

	nodeInstance := NewMocknodeBuilderIface(ctrl)
	nodeInstance.EXPECT().createStateService(cfg)

	stateSrvc, err := nodeInstance.createStateService(cfg)
	require.NoError(t, err)

	nodeInstance.EXPECT().createRuntimeStorage(stateSrvc)

	ks := keystore.NewGlobalKeystore()
	kr, err := keystore.NewSr25519Keyring()
	require.NoError(t, err)
	ks.Babe.Insert(kr.Alice())

	ns, err := nodeInstance.createRuntimeStorage(stateSrvc)
	require.NoError(t, err)

	nodeInstance.EXPECT().loadRuntime(cfg, ns, stateSrvc, ks, &network.Service{})

	err = nodeInstance.loadRuntime(cfg, ns, stateSrvc, ks, &network.Service{})
	require.NoError(t, err)

	nodeInstance.EXPECT().createDigestHandler(cfg.Log.StateLvl, stateSrvc)
	dh, err := nodeInstance.createDigestHandler(cfg.Log.StateLvl, stateSrvc)
	require.NoError(t, err)

	nodeInstance.EXPECT().createCoreService(cfg, ks, stateSrvc, &network.Service{}, dh)
	coreSrvc, err := nodeInstance.createCoreService(cfg, ks, stateSrvc, &network.Service{}, dh)
	require.NoError(t, err)

	nodeInstance.EXPECT().createBABEService(cfg, stateSrvc, gomock.Any(),
		coreSrvc, nil).DoAndReturn(func(cfg *Config, st *state.Service, ks keystore.Keystore, cs *core.Service,
		telemetryMailer telemetry.Client) (*babe.Service, error) {
		if ks.Type() != crypto.Sr25519Type {
			return nil, errors.New("invalid keystore type")
		}
		return &babe.Service{}, nil
	}).Times(2)
	type args struct {
		cfg *Config
		st  *state.Service
		ks  keystore.Keystore
		cs  *core.Service
	}
	tests := []struct {
		name string
		args args
		want *babe.Service
		err  error
	}{
		{
			name: "invalid keystore type test",
			args: args{
				cfg: cfg,
				st:  stateSrvc,
				ks:  ks.Gran,
				cs:  coreSrvc,
			},
			err: errors.New("invalid keystore type"),
		},
		{
			name: "working example",
			args: args{
				cfg: cfg,
				st:  stateSrvc,
				ks:  ks.Babe,
				cs:  coreSrvc,
			},
			want: &babe.Service{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeInstance.createBABEService(tt.args.cfg, tt.args.st, tt.args.ks, tt.args.cs, nil)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_createBlockVerifier(t *testing.T) {
	cfg := NewTestConfig(t)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Init.Genesis = genFile

	nodeInstance := nodeBuilder{}
	err := nodeInstance.initNode(cfg)
	require.NoError(t, err)

	stateSrvc, err := nodeInstance.createStateService(cfg)
	require.NoError(t, err)

	stateSrvc.Block = &state.BlockState{}
	stateSrvc.Epoch = &state.EpochState{}

	type args struct {
		st *state.Service
	}
	tests := []struct {
		name string
		args args
		want *babe.VerificationManager
		err  error
	}{
		{
			name: "nil BlockState test",
			args: args{st: &state.Service{}},
			err:  errors.New("cannot have nil BlockState"),
		},
		{
			name: "working example",
			args: args{st: stateSrvc},
			want: &babe.VerificationManager{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeInstance.createBlockVerifier(tt.args.st)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_createCoreService(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfg := NewTestConfig(t)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Core.Roles = types.FullNodeRole
	cfg.Core.BabeAuthority = false
	cfg.Core.GrandpaAuthority = false
	cfg.Init.Genesis = genFile

	nodeInstance := NewMocknodeBuilderIface(ctrl)
	nodeInstance.EXPECT().createStateService(cfg)

	stateSrvc, err := nodeInstance.createStateService(cfg)
	require.NoError(t, err)

	nodeInstance.EXPECT().createNetworkService(cfg, stateSrvc, nil)

	networkSrvc, err := nodeInstance.createNetworkService(cfg, stateSrvc, nil)
	require.NoError(t, err)

	ks := keystore.NewGlobalKeystore()
	require.NotNil(t, ks)
	ed25519Keyring, _ := keystore.NewEd25519Keyring()
	ks.Gran.Insert(ed25519Keyring.Alice())

	nodeInstance.EXPECT().createCoreService(cfg, gomock.AssignableToTypeOf(&keystore.GlobalKeystore{}), stateSrvc,
		networkSrvc, nil).DoAndReturn(func(cfg *Config, ks *keystore.GlobalKeystore, st *state.Service, net *network.Service,
		dh *digest.Handler) (*core.Service, error) {
		if ks == nil {
			return nil, errors.New("cannot have nil keystore")
		}
		return &core.Service{}, nil
	}).Times(2)

	type args struct {
		cfg *Config
		ks  *keystore.GlobalKeystore
		st  *state.Service
		net *network.Service
		dh  *digest.Handler
	}
	tests := []struct {
		name string
		args args
		want *core.Service
		err  error
	}{
		{
			name: "missing keystore test",
			args: args{
				cfg: cfg,
				st:  stateSrvc,
			},
			err: errors.New("cannot have nil keystore"),
		},
		{
			name: "working example",
			args: args{
				cfg: cfg,
				ks:  ks,
				st:  stateSrvc,
				net: networkSrvc,
			},
			want: &core.Service{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeInstance.createCoreService(tt.args.cfg, tt.args.ks, tt.args.st, tt.args.net, tt.args.dh)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}
			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_createDigestHandler(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfg := NewTestConfig(t)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Init.Genesis = genFile

	nodeInstance := NewMocknodeBuilderIface(ctrl)
	nodeInstance.EXPECT().createStateService(cfg)
	stateSrvc, err := nodeInstance.createStateService(cfg)
	require.NoError(t, err)
	nodeInstance.EXPECT().createDigestHandler(log.Critical, stateSrvc).Return(&digest.Handler{}, nil)

	type args struct {
		st *state.Service
	}
	tests := []struct {
		name string
		args args
		want *digest.Handler
		err  error
	}{
		{
			name: "working example",
			args: args{st: stateSrvc},
			want: &digest.Handler{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeInstance.createDigestHandler(log.Critical, tt.args.st)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_createGRANDPAService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfg := NewTestConfig(t)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Core.Roles = types.AuthorityRole
	cfg.Init.Genesis = genFile

	ks := keystore.NewGlobalKeystore()
	kr, err := keystore.NewEd25519Keyring()
	require.NoError(t, err)
	ks.Gran.Insert(kr.Alice())

	type args struct {
		cfg *Config
		st  *state.Service
		dh  *digest.Handler
		ks  keystore.Keystore
		net *network.Service
	}
	tests := []struct {
		name string
		args args
		want *grandpa.Service
		err  error
	}{
		{
			name: "invalid key type test",
			args: args{
				cfg: cfg,
				ks:  ks.Babe,
			},
			err: errors.New("invalid keystore type"),
		},
		{
			name: "working example",
			args: args{
				cfg: cfg,
				ks:  ks.Gran,
			},
			want: &grandpa.Service{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockNodeIface := NewMocknodeBuilderIface(ctrl)
			mockNodeIface.EXPECT().createGRANDPAService(tt.args.cfg, nil, nil, tt.args.ks,
				nil, nil).DoAndReturn(func(cfg *Config, st *state.Service, dh *digest.Handler, ks keystore.Keystore,
				net *network.Service, telemetryMailer telemetry.Client) (*grandpa.Service, error) {
				if ks.Name() != "gran" || ks.Type() != crypto.Ed25519Type {
					return nil, ErrInvalidKeystoreType
				}
				return &grandpa.Service{}, nil
			})
			got, err := mockNodeIface.createGRANDPAService(tt.args.cfg, tt.args.st, tt.args.dh, tt.args.ks,
				tt.args.net, nil)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_createNetworkService(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfg := NewTestConfig(t)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Init.Genesis = genFile

	nodeInstance := NewMocknodeBuilderIface(ctrl)
	nodeInstance.EXPECT().createStateService(cfg)
	stateSrvc, err := nodeInstance.createStateService(cfg)
	require.NoError(t, err)
	nodeInstance.EXPECT().createNetworkService(cfg, stateSrvc, nil).Return(&network.Service{}, nil)

	type args struct {
		cfg       *Config
		stateSrvc *state.Service
	}
	tests := []struct {
		name string
		args args
		want *network.Service
		err  error
	}{
		{
			name: "working example",
			args: args{
				cfg:       cfg,
				stateSrvc: stateSrvc,
			},
			want: &network.Service{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeInstance.createNetworkService(tt.args.cfg, tt.args.stateSrvc, nil)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_createRPCService(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfg := NewTestConfig(t)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Core.Roles = types.FullNodeRole
	cfg.Core.BabeAuthority = false
	cfg.Core.GrandpaAuthority = false
	cfg.Init.Genesis = genFile

	nodeInstance := NewMocknodeBuilderIface(ctrl)
	nodeInstance.EXPECT().createStateService(cfg)

	stateSrvc, err := nodeInstance.createStateService(cfg)
	require.NoError(t, err)
	nodeInstance.EXPECT().createRPCService(cfg, nil, stateSrvc, nil, nil, nil, nil, nil).Return(&rpc.HTTPServer{}, nil)

	type args struct {
		cfg         *Config
		ns          *runtime.NodeStorage
		stateSrvc   *state.Service
		coreSrvc    *core.Service
		networkSrvc *network.Service
		bp          modules.BlockProducerAPI
		sysSrvc     *system.Service
		finSrvc     *grandpa.Service
	}
	tests := []struct {
		name string
		args args
		want *rpc.HTTPServer
		err  error
	}{
		{
			name: "working example",
			args: args{
				cfg:       cfg,
				stateSrvc: stateSrvc,
			},
			want: &rpc.HTTPServer{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeInstance.createRPCService(tt.args.cfg, tt.args.ns, tt.args.stateSrvc, tt.args.coreSrvc,
				tt.args.networkSrvc, tt.args.bp, tt.args.sysSrvc, tt.args.finSrvc)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_createRuntimeStorage(t *testing.T) {
	cfg := NewTestConfig(t)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Init.Genesis = genFile

	nodeInstance := nodeBuilder{}
	err := nodeInstance.initNode(cfg)
	require.NoError(t, err)

	stateSrvc, err := nodeInstance.createStateService(cfg)
	require.NoError(t, err)

	type args struct {
		st *state.Service
	}
	tests := []struct {
		name string
		args args
		want *runtime.NodeStorage
		err  error
	}{
		{
			name: "working example",
			args: args{st: stateSrvc},
			want: &runtime.NodeStorage{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeInstance.createRuntimeStorage(tt.args.st)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_createStateService(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfg := NewTestConfig(t)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Init.Genesis = genFile

	nodeInstance := NewMocknodeBuilderIface(ctrl)
	nodeInstance.EXPECT().createStateService(gomock.AssignableToTypeOf(&Config{})).DoAndReturn(func(config *Config) (
		*state.Service, error) {
		if config.Global.BasePath == "test_data" {
			return nil, errors.New("failed to start state service: failed to create block state: cannot get block 0" +
				": Key not found")
		}
		return &state.Service{}, nil
	}).Times(2)

	cfg2 := NewTestConfig(t)
	cfg2.Global.BasePath = "test_data"

	type args struct {
		cfg *Config
	}
	tests := []struct {
		name string
		args args
		want *state.Service
		err  error
	}{
		{
			name: "working example",
			args: args{cfg: cfg},
			want: &state.Service{},
		},
		{
			name: "broken config test",
			args: args{cfg: cfg2},
			err:  errors.New("failed to start state service: failed to create block state: cannot get block 0: Key not found"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeInstance.createStateService(tt.args.cfg)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_createSystemService(t *testing.T) {
	cfg := NewTestConfig(t)

	genFile := NewTestGenesisRawFile(t, cfg)

	cfg.Init.Genesis = genFile

	nodeInstance := nodeBuilder{}
	err := nodeInstance.initNode(cfg)
	require.NoError(t, err)

	stateSrvc, err := nodeInstance.createStateService(cfg)
	require.NoError(t, err)

	type args struct {
		cfg       *types.SystemInfo
		stateSrvc *state.Service
	}
	tests := []struct {
		name string
		args args
		want *system.Service
		err  error
	}{
		{
			name: "working example",
			args: args{
				stateSrvc: stateSrvc,
			},
			want: &system.Service{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeInstance.createSystemService(tt.args.cfg, tt.args.stateSrvc)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_newInMemoryDB(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name string
		args args
		want bool
		err  error
	}{
		{
			name: "working example",
			args: args{path: "test_data"},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newInMemoryDB(tt.args.path)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func Test_newSyncService(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfg := NewTestConfig(t)

	genFile := newTestGenesisFile(t, cfg)

	cfg.Init.Genesis = genFile

	nodeInstance := NewMocknodeBuilderIface(ctrl)
	nodeInstance.EXPECT().createStateService(cfg)

	stateSrvc, err := nodeInstance.createStateService(cfg)
	require.NoError(t, err)
	nodeInstance.EXPECT().newSyncService(cfg, stateSrvc, gomock.Any(), nil, nil,
		nil,
		nil).DoAndReturn(func(cfg *Config,
		st *state.Service, fg sync.FinalityGadget, verifier *babe.VerificationManager,
		cs *core.Service, net *network.Service, telemetryMailer telemetry.Client) (*sync.Service, error) {
		if fg == nil {
			return nil, errors.New("cannot have nil FinalityGadget")
		}
		return &sync.Service{}, nil
	}).Times(2)
	type args struct {
		cfg      *Config
		st       *state.Service
		fg       sync.FinalityGadget
		verifier *babe.VerificationManager
		cs       *core.Service
		net      *network.Service
	}
	tests := []struct {
		name string
		args args
		want *sync.Service
		err  error
	}{
		{
			name: "missing FinalityGadget test",
			args: args{
				cfg: cfg,
				st:  stateSrvc,
			},
			err: errors.New("cannot have nil FinalityGadget"),
		},
		{
			name: "working example",
			args: args{
				cfg: cfg,
				st:  stateSrvc,
				fg:  &grandpa.Service{},
			},
			want: &sync.Service{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeInstance.newSyncService(tt.args.cfg, tt.args.st, tt.args.fg, tt.args.verifier, tt.args.cs,
				tt.args.net, nil)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.want != nil {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}
