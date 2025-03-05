package provider

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var _ adapter.ProviderManager = (*Manager)(nil)

type Manager struct {
	logger        log.ContextLogger
	registry      adapter.ProviderRegistry
	access        sync.Mutex
	started       bool
	stage         adapter.StartStage
	providers     []adapter.Provider
	providerByTag map[string]adapter.Provider
}

func NewManager(logger logger.ContextLogger, registry adapter.ProviderRegistry) *Manager {
	return &Manager{
		logger:        logger,
		registry:      registry,
		providerByTag: make(map[string]adapter.Provider),
	}
}

func (m *Manager) Initialize() {
}

func (m *Manager) Start(stage adapter.StartStage) error {
	m.access.Lock()
	if m.started && m.stage >= stage {
		panic("already started")
	}
	m.started = true
	m.stage = stage
	providers := m.providers
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		return m.startProviders(providers)
	}
	return nil
}

func (m *Manager) startProviders(providers []adapter.Provider) error {
	monitor := taskmonitor.New(m.logger, C.StartTimeout)
	started := make(map[string]bool)
	for {
		for _, providerToStart := range providers {
			providerTag := providerToStart.Tag()
			if started[providerTag] {
				continue
			}
			started[providerTag] = true
			if starter, isStarter := providerToStart.(adapter.Lifecycle); isStarter {
				monitor.Start("start provider", "[", providerTag, "]")
				err := starter.Start(adapter.StartStateStart)
				monitor.Finish()
				if err != nil {
					return E.Cause(err, "start provider", "[", providerTag, "]")
				}
			} else if starter, isStarter := providerToStart.(interface {
				Start() error
			}); isStarter {
				monitor.Start("start provider", "[", providerTag, "]")
				err := starter.Start()
				monitor.Finish()
				if err != nil {
					return E.Cause(err, "start provider", "[", providerTag, "]")
				}
			}
		}
		if len(started) == len(providers) {
			break
		}
	}
	return nil
}

func (m *Manager) Close() error {
	monitor := taskmonitor.New(m.logger, C.StopTimeout)
	m.access.Lock()
	if !m.started {
		m.access.Unlock()
		return nil
	}
	m.started = false
	providers := m.providers
	m.providers = nil
	m.access.Unlock()
	var err error
	for _, provider := range providers {
		if closer, isCloser := provider.(io.Closer); isCloser {
			monitor.Start("close provider/", "[", provider.Tag(), "]")
			err = E.Append(err, closer.Close(), func(err error) error {
				return E.Cause(err, "close provider/", "[", provider.Tag(), "]")
			})
			monitor.Finish()
		}
	}
	return nil
}

func (m *Manager) Providers() []adapter.Provider {
	m.access.Lock()
	defer m.access.Unlock()
	return m.providers
}

func (m *Manager) Provider(tag string) (adapter.Provider, bool) {
	m.access.Lock()
	provider, found := m.providerByTag[tag]
	m.access.Unlock()
	return provider, found
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	provider, found := m.providerByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.providerByTag, tag)
	index := common.Index(m.providers, func(it adapter.Provider) bool {
		return it == provider
	})
	if index == -1 {
		panic("invalid provider index")
	}
	m.providers = append(m.providers[:index], m.providers[index+1:]...)
	started := m.started
	m.access.Unlock()
	if started {
		return common.Close(provider)
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, providerType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}

	provider, err := m.registry.CreateProvider(ctx, router, logFactory, tag, providerType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.started {
		for _, stage := range adapter.ListStartStages {
			err = adapter.LegacyStart(provider, stage)
			if err != nil {
				return E.Cause(err, stage, " provider/", "[", provider.Tag(), "]")
			}
		}
	}
	if existsProvider, loaded := m.providerByTag[tag]; loaded {
		if m.started {
			err = common.Close(existsProvider)
			if err != nil {
				return E.Cause(err, "close provider", "[", existsProvider.Tag(), "]")
			}
		}
		existsIndex := common.Index(m.providers, func(it adapter.Provider) bool {
			return it == existsProvider
		})
		if existsIndex == -1 {
			panic("invalid provider index")
		}
		m.providers = append(m.providers[:existsIndex], m.providers[existsIndex+1:]...)
	}
	m.providers = append(m.providers, provider)
	m.providerByTag[tag] = provider
	return nil
}
