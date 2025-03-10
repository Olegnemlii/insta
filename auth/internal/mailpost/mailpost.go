package mailpost

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	apiURL = "https://api.mailopost.ru/v1/"
)

type Client struct {
	APIKey    string
	APISecret string
}

func NewClient(apiKey, apiSecret string) *Client {
	return &Client{APIKey: apiKey, APISecret: apiSecret}
}

func (c *Client) SendMessage(to, subject, body string) error {
	msg := Message{
		To:      to,
		Subject: subject,
		Body:    body,
	}

	jsonMsg, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiURL+"messages", bytes.NewBuffer(jsonMsg))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.APIKey))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}

	return nil
}

type Message struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}
