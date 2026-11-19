package connectsecure

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// SASEmoji is the table a pairing's short authentication string is drawn from: 64 emoji that are easy
// to tell apart and render on every phone and computer TailPocket supports (Unicode 8 or older, no
// variation selectors). SASNames are their English names, for screen readers.
var SASEmoji = [64]string{
	"🐶", "🐱", "🦁", "🐴", "🦄", "🐷", "🐘", "🐰",
	"🐼", "🐔", "🐧", "🐢", "🐟", "🐙", "🐝", "🐌",
	"🌸", "🌳", "🌵", "🍄", "🌍", "🌙", "🌟", "🔥",
	"💧", "🌈", "🍎", "🍌", "🍇", "🍓", "🍉", "🍒",
	"🌽", "🍞", "🧀", "🍕", "🎂", "🍩", "🍺", "🍔",
	"🏀", "🎸", "🎺", "🔔", "🔑", "🔨", "📎", "📚",
	"💡", "🚗", "🚲", "🚀", "🚂", "⏰", "🎁", "👓",
	"🎩", "👑", "💎", "🎈", "🐸", "🐳", "🍀", "🍋",
}

var SASNames = [64]string{
	"dog", "cat", "lion", "horse", "unicorn", "pig", "elephant", "rabbit",
	"panda", "chicken", "penguin", "turtle", "fish", "octopus", "bee", "snail",
	"blossom", "tree", "cactus", "mushroom", "globe", "moon", "star", "fire",
	"drop", "rainbow", "apple", "banana", "grapes", "strawberry", "watermelon", "cherries",
	"corn", "bread", "cheese", "pizza", "cake", "doughnut", "beer", "burger",
	"basketball", "guitar", "trumpet", "bell", "key", "hammer", "paperclip", "books",
	"light bulb", "car", "bicycle", "rocket", "train", "alarm clock", "gift", "glasses",
	"top hat", "crown", "gem", "balloon", "frog", "whale", "clover", "lemon",
}

// SAS is the pairing's short authentication string: four indexes into SASEmoji, taken from
// HKDF-SHA256(binding, "tailpocket2 sas"), 6 bits each. binding is the handshake hash
// (Session.ChannelBinding); both sides of one handshake get the same four, any other session gets
// four that match by chance once in 2^24.
func SAS(binding []byte) [4]int {
	b, err := hkdf.Key(sha256.New, binding, nil, "tailpocket2 sas", 3)
	if err != nil {
		panic(err) // only for a length HKDF cannot produce
	}
	v := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return [4]int{v >> 18 & 63, v >> 12 & 63, v >> 6 & 63, v & 63}
}

// SASText is SAS as emoji.
func SASText(binding []byte) []string {
	idx := SAS(binding)
	out := make([]string, len(idx))
	for i, n := range idx {
		out[i] = SASEmoji[n]
	}
	return out
}
