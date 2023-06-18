package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

var bot *tgbotapi.BotAPI

type TgState int

const (
	StRoot TgState = iota
	StSnippet
)

type TgUser struct {
	st TgState
	id int64
}

var users map[int64]*TgUser

func trySendSnippet(u *TgUser, idStr string) {
	id, err := strconv.Atoi(idStr)
	var response tgbotapi.MessageConfig
	if err == nil {
		snippet, err := getSnippet(db, id, true)
		if err != nil {
			logger.Error(err.Error())
			response = tgbotapi.NewMessage(u.id, "error")
			bot.Send(response)
			return
		}
		response = tgbotapi.NewMessage(u.id, string(snippet.Content))
		if snippet.Type == "markdown" {
			response.ParseMode = "Markdown"
		}
		logger.Debug(fmt.Sprintf("snippet type is %s, parse_mode is %s", snippet.Type, response.ParseMode))
		bot.Send(response)
		return
	}
	response = tgbotapi.NewMessage(u.id, "Wrong id")
	bot.Send(response)
	return

}

func cmdSnippet(u *TgUser, update *tgbotapi.Update) {
	msg := update.Message.Text
	var response tgbotapi.MessageConfig

	cmd := update.Message.Command()
	if cmd != "" {
		msg_s := strings.Split(msg, " ")
		if len(msg_s) > 1 {
			u.st = StRoot
			trySendSnippet(u, msg_s[1])
			return

		} else {
			response = tgbotapi.NewMessage(update.Message.Chat.ID, "send me id")
			bot.Send(response)
			return
		}
	} else {
		u.st = StRoot
		trySendSnippet(u, msg)
		return
	}
}

func bot_run() {
	users = make(map[int64]*TgUser)
	file, err := os.Open("token")
	if err != nil {
		logger.Error(err.Error())
		return
	}
	tokenb, err := io.ReadAll(file)
	token := strings.TrimSpace(string(tokenb))
	if err != nil {
		logger.Error(err.Error())
		return
	}
	bot, err = tgbotapi.NewBotAPI(token)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	updateConfig := tgbotapi.NewUpdate(0)

	// Tell Telegram we should wait up to 30 seconds on each request for an
	// update. This way we can get information just as quickly as making many
	// frequent requests without having to send nearly as many.
	updateConfig.Timeout = 30
	updates := bot.GetUpdatesChan(updateConfig)

	// Let's go through each update that we're getting from Telegram.
	for update := range updates {
		// Telegram can send many types of updates depending on what your Bot
		// is up to. We only want to look at messages for now, so we can
		// discard any other updates.
		if update.Message == nil {
			continue
		}
		logger.Debug(fmt.Sprintf("message %s from %d (%s), chatid %d", update.Message.Text, update.Message.From.ID, update.Message.From.String(), update.Message.Chat.ID))
		cmd := update.Message.Command()
		logger.Debug(fmt.Sprintf("cmd is %s", cmd))
		from := update.Message.From.ID
		if from == 0 {
			logger.Error("zero id")
			continue
		}
		var msg tgbotapi.MessageConfig
		if from != config.Bot.AdminID {
			msg = tgbotapi.NewMessage(update.Message.Chat.ID, "not allowed")
			bot.Send(msg)
			continue
		}
		u, ok := users[from]
		if !ok {
			u = new(TgUser)
			u.id = update.Message.From.ID
			users[from] = u
		}
		switch cmd {
		case "snippet":
			u.st = StSnippet
		case "":
			break
		default:
			u.st = StRoot
			msg = tgbotapi.NewMessage(update.Message.Chat.ID, "?")
			bot.Send(msg)
			continue
		}
		switch u.st {
		case StSnippet:
			cmdSnippet(u, &update)
		default:
			logger.Error("How did I get here?")

		}

	}
}
