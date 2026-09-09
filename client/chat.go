package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/xeprotocol/xe/chat"
	"github.com/xeprotocol/xe/directory"
)

func (c *Client) RegisterDirectory(reg *directory.Registration) error {
	return c.do(http.MethodPost, c.BaseURL+"/directory/register", reg, nil)
}

func (c *Client) LookupDirectory(account string) (*directory.Registration, error) {
	var reg directory.Registration
	if err := c.do(http.MethodGet, c.BaseURL+"/directory/"+account, nil, &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

func (c *Client) ChatPoWDifficulty() (uint64, error) {
	info, err := c.NodeInfo()
	if err != nil {
		return 0, err
	}
	s, _ := info["chat_pow_difficulty"].(string)
	if s == "" {
		return 0, fmt.Errorf("node advertises no chat_pow_difficulty")
	}
	return strconv.ParseUint(s, 16, 64)
}

func (c *Client) SendChat(env *chat.Envelope) error {
	return c.do(http.MethodPost, c.BaseURL+"/chat/send", env, nil)
}

func (c *Client) ChatChallenge() (string, error) {
	var out struct {
		Challenge string `json:"challenge"`
	}
	if err := c.do(http.MethodGet, c.BaseURL+"/chat/auth/challenge", nil, &out); err != nil {
		return "", err
	}
	if out.Challenge == "" {
		return "", fmt.Errorf("empty challenge")
	}
	return out.Challenge, nil
}

func (c *Client) ChatMessages(account, pubKey, challenge, sig string, since int64) ([]*chat.Envelope, error) {
	q := url.Values{}
	q.Set("account", account)
	q.Set("pub_key", pubKey)
	q.Set("challenge", challenge)
	q.Set("sig", sig)
	q.Set("since", strconv.FormatInt(since, 10))
	var msgs []*chat.Envelope
	if err := c.do(http.MethodGet, c.BaseURL+"/chat/messages?"+q.Encode(), nil, &msgs); err != nil {
		return nil, err
	}
	return msgs, nil
}

func (c *Client) do(method, url string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(resp.Body)
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(raw))
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return fmt.Errorf("%d %s", resp.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
