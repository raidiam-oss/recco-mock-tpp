package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/raidiam/recco-mock-tpp/shared/model"
)

type ParticipantCache struct {
	sync.RWMutex
	participants  []model.Participant
	cacheEndpoint string
}

func NewParticipantCache(ctx context.Context, endpoint string) (*ParticipantCache, error) {
	participants, err := getParticipants(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return &ParticipantCache{
		participants:  participants,
		cacheEndpoint: endpoint,
	}, nil
}

func (c *ParticipantCache) Participants() []model.Participant {
	c.RLock()
	defer c.RUnlock()
	return c.participants
}

func (c *ParticipantCache) SetParticipants(participants []model.Participant) {
	c.Lock()
	defer c.Unlock()
	c.participants = participants
}

func (c *ParticipantCache) Clear() {
	c.Lock()
	defer c.Unlock()
	c.participants = nil
}

func (c *ParticipantCache) AuthServers() []model.AuthServer {
	c.RLock()
	defer c.RUnlock()

	var authServers []model.AuthServer
	for _, participant := range c.participants {
		authServers = append(authServers, participant.AuthServers...)
	}
	if authServers == nil {
		return []model.AuthServer{}
	}
	return authServers
}

func (c *ParticipantCache) Refresh(ctx context.Context) ([]model.Participant, error) {
	c.Lock()
	defer c.Unlock()
	participants, err := getParticipants(ctx, c.cacheEndpoint)
	if err != nil {
		return nil, err
	}
	c.participants = participants
	return participants, nil
}

func RefreshParticipantCache(ctx context.Context, cache *ParticipantCache, interval time.Duration, updateChan chan<- model.UpdateMessage) {
	for {
		_, err := cache.Refresh(ctx)
		if err != nil {
			message := model.UpdateMessage{
				Message: fmt.Sprintf("error refreshing participant cache: %v", err),
				Updated: false,
			}
			updateChan <- message
		}
		message := model.UpdateMessage{
			Message: "participant cache updated",
			Updated: true,
		}
		updateChan <- message
		time.Sleep(interval)
	}
}

func getParticipants(ctx context.Context, endpoint string) ([]model.Participant, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("participants request build failed: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("participants fetch failed: %w", err)
	}
	defer resp.Body.Close()

	var parts []model.Participant
	if err := json.NewDecoder(resp.Body).Decode(&parts); err != nil {
		return nil, fmt.Errorf("participants decode failed: %w", err)
	}

	return parts, nil
}
