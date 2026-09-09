package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xeprotocol/xe/chat"
	"github.com/xeprotocol/xe/client"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
)

const chatAuthDomain = "xe/chat-read-auth/v1\x00"

const directoryRefresh = directory.DefaultTTL * 2 / 3

const directoryRetry = time.Minute

const chatFollowInterval = 5 * time.Second

func cmdDirectory(args []string) {
	if len(args) == 0 || args[0] != "register" {
		fatal("usage: xe directory register [--watch]")
	}
	watch := false
	for _, a := range args[1:] {
		if a != "--watch" {
			fatal("unknown flag %q\nusage: xe directory register [--watch]", a)
		}
		watch = true
	}
	initNetworkID()
	kp := loadWallet()
	c := apiClient()

	peer, err := directoryRegister(c, kp)
	if err != nil {
		fatal("directory register: %v", err)
	}
	fmt.Printf("Registered %s\n", kp.Address())
	fmt.Printf("  Node: %s\n", peer)
	if !watch {
		return
	}
	fmt.Printf("  Re-registering every %s (Ctrl-C to stop)\n", directoryRefresh)
	wait := directoryRefresh
	for {
		time.Sleep(wait)
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := directoryRegister(c, kp); err != nil {

			fmt.Fprintf(os.Stderr, "%s re-register failed: %v (retry in %s)\n", now, err, directoryRetry)
			wait = directoryRetry
			continue
		}
		fmt.Printf("%s re-registered\n", now)
		wait = directoryRefresh
	}
}

func directoryRegister(c *client.Client, kp *core.KeyPair) (string, error) {
	info, err := c.NodeInfo()
	if err != nil {
		return "", err
	}
	peer, _ := info["id"].(string)
	if peer == "" {
		return "", fmt.Errorf("node reports no peer id")
	}
	reg := directory.NewRegistration(peer, time.Now().UnixNano(), kp)
	if err := c.RegisterDirectory(reg); err != nil {
		return "", err
	}
	return peer, nil
}

func cmdChat(args []string) {
	if len(args) == 0 {
		fatal("usage: xe chat <send|read> ...")
	}
	switch args[0] {
	case "send":
		if len(args) < 3 {
			fatal("usage: xe chat send <to-address> <message>")
		}
		cmdChatSend(args[1], strings.Join(args[2:], " "))
	case "read":
		cmdChatRead(args[1:])

	default:
		fatal("unknown chat command: %s", args[0])
	}
}

func cmdChatSend(to, message string) {
	kp := loadWallet()
	c := apiClient()

	id, err := chatSend(c, kp, to, message)
	if err != nil {
		fatal("chat send: %v", err)
	}
	fmt.Printf("Sent %d bytes to %s\n", len(message), shortAddr(to))
	fmt.Printf("  ID: %s\n", id)
}

func chatSend(c *client.Client, kp *core.KeyPair, to, message string) (string, error) {
	difficulty, err := c.ChatPoWDifficulty()
	if err != nil {
		return "", err
	}
	env, err := chat.NewEnvelope(kp.Address(), to, message, kp, difficulty)
	if err != nil {
		return "", err
	}
	if err := c.SendChat(env); err != nil {
		return "", err
	}
	return env.ID, nil
}

type chatReadArgs struct {
	since  int64
	follow bool
	json   bool
}

func parseChatReadArgs(args []string) (chatReadArgs, error) {
	var a chatReadArgs
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--since":
			if i+1 >= len(args) {
				return a, fmt.Errorf("--since requires a value (unix nanoseconds)")
			}
			i++
			n, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || n < 0 {
				return a, fmt.Errorf("--since must be unix nanoseconds, got %q", args[i])
			}
			a.since = n
		case "--follow":
			a.follow = true
		case "--json":
			a.json = true
		default:
			return a, fmt.Errorf("unknown flag %q", args[i])
		}
	}
	return a, nil
}

func cmdChatRead(args []string) {
	a, err := parseChatReadArgs(args)
	if err != nil {
		fatal("%v\nusage: xe chat read [--since <unix-ns>] [--follow] [--json]", err)
	}
	kp := loadWallet()
	c := apiClient()

	seen := map[string]bool{}
	for {
		msgs, err := chatRead(c, kp, a.since)
		if err != nil {
			if !a.follow {
				fatal("chat read: %v", err)
			}
			fmt.Fprintf(os.Stderr, "chat read: %v\n", err)
		}
		for _, env := range msgs {
			if seen[env.ID] {
				continue
			}
			seen[env.ID] = true
			if err := printEnvelope(os.Stdout, env, a.json); err != nil {
				fatal("chat read: %v", err)
			}
		}
		if !a.follow {
			if len(msgs) == 0 && !a.json {
				fmt.Println("No messages.")
			}
			return
		}
		time.Sleep(chatFollowInterval)
	}
}

func chatSignChallenge(kp *core.KeyPair, challenge string) (string, error) {
	tokenBytes, err := hex.DecodeString(challenge)
	if err != nil {
		return "", fmt.Errorf("malformed challenge: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(chatAuthDomain))
	h.Write(tokenBytes)
	return hex.EncodeToString(ed25519.Sign(kp.Private, h.Sum(nil))), nil
}

func chatRead(c *client.Client, kp *core.KeyPair, since int64) ([]*chat.Envelope, error) {
	challenge, err := c.ChatChallenge()
	if err != nil {
		return nil, err
	}
	sig, err := chatSignChallenge(kp, challenge)
	if err != nil {
		return nil, err
	}
	return c.ChatMessages(kp.Address(), kp.PubKeyHex(), challenge, sig, since)
}

func printEnvelope(w io.Writer, env *chat.Envelope, asJSON bool) error {
	if asJSON {
		data, err := json.Marshal(env)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s\n", data)
		return err
	}
	ts := time.Unix(0, env.Timestamp).UTC().Format(time.RFC3339)
	_, err := fmt.Fprintf(w, "%s %s -> %s %s\n", ts, env.From, env.To, env.Message)
	return err
}
