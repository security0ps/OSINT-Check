package ioc

import (
	"errors"
	"strings"
	"unicode"
)

// Punycode nach RFC 3492, damit IDN-Domains wie bücher.example geprüft werden können.
const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

func toASCII(host string) (string, error) {
	ascii := true
	for _, r := range host {
		if r > unicode.MaxASCII {
			ascii = false
			break
		}
	}
	if ascii {
		return host, nil
	}
	labels := strings.Split(strings.Map(unicode.ToLower, host), ".")
	for i, label := range labels {
		enc, err := encodeLabel(label)
		if err != nil {
			return "", err
		}
		labels[i] = enc
	}
	return strings.Join(labels, "."), nil
}

func encodeLabel(label string) (string, error) {
	runes := []rune(label)
	var b strings.Builder
	for _, r := range runes {
		if r <= unicode.MaxASCII {
			b.WriteRune(r)
		}
	}
	basic := b.Len()
	if basic == len(runes) {
		return label, nil
	}
	if basic > 0 {
		b.WriteByte('-')
	}
	n, delta, bias, handled := pcInitialN, 0, pcInitialBias, basic
	for handled < len(runes) {
		m := int(unicode.MaxRune) + 1
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if m-n > (1<<30)/(handled+1) {
			return "", errors.New("punycode overflow")
		}
		delta += (m - n) * (handled + 1)
		n = m
		for _, r := range runes {
			if int(r) < n {
				delta++
			}
			if int(r) == n {
				q := delta
				for k := pcBase; ; k += pcBase {
					t := k - bias
					if t < pcTMin {
						t = pcTMin
					} else if t > pcTMax {
						t = pcTMax
					}
					if q < t {
						break
					}
					b.WriteByte(pcDigit(t + (q-t)%(pcBase-t)))
					q = (q - t) / (pcBase - t)
				}
				b.WriteByte(pcDigit(q))
				bias = pcAdapt(delta, handled+1, handled == basic)
				delta = 0
				handled++
			}
		}
		delta++
		n++
	}
	return "xn--" + b.String(), nil
}

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func pcAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}
