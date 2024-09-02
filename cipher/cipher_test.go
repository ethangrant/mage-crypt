package cipher

import (
	"fmt"
	"testing"
)

type DecryptTestCase struct {
	ciphertext string
	plaintext  string
	key        string
}

func TestChacha20poly1305Decrypt(t *testing.T) {
	// these test cases have ben generated using magento 2.4.6
	testCases := []DecryptTestCase{
		{ciphertext: "1:3:2aqoxrtf4k7Al5Vrup8xG6h580WmNSjnyvDwonhWY1NUNDbSwTb4petZija6SvWvkUxt55IL", plaintext: "May the Force be with you.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:Ar/1woujlZ6c38Dx3WPGMhyEEPXCqoRl4Z5EjFb0xMUI46lPlqGnh3phRg8HxK18S1B55kJtBPAYHHKUiTKEKiivOB/jf+AR", plaintext: "I'm gonna make him an offer he can't refuse.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:6UkL2/E6qrMLO32MHug81i5sMboNMZnYFZO9xfDYqNoHQpAvMAVxqLvcEPZKIw==", plaintext: "You talking to me?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:bqrMz5wxybzOIDVf1NO+0LDbuuQYe7vcNNTuKWkad0W45TheqWsGw5OE+Eb61agZUYlw1+BJtA==", plaintext: "Here's looking at you, kid.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:VGPrZUdRHxGAY9y932dC1u67eoEcAx/gVNqj4CXaxFpZac6Jw+pardKnOk3z93vnFf0=", plaintext: "Go ahead, make my day.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:ipG0+caAaLuxd3+2Uehj4QV50j6P2t49d/QCgMHTOl9wcvxjioCDzr0=", plaintext: "I'll be back.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:kMu/pcPUnXkfFDL8pO/s/7lyHzY5wWJ+jj86CleKdUYaqs6VL8GBgEolROGdBWnDUudTur/69w==", plaintext: "Houston, we have a problem.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:hqYwIto1PekcfR016N9Dmytpr72yowvsT1gob249mI1PhOvixPY2FKajlB+5WslFdj2VXcaDzGI07K4C", plaintext: "You're gonna need a bigger boat.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:8u5XABkue4wuvGG2OT+f7P0KmUH6aoY2MI1Eu7YBSgCbnDaXeCKLVf9iOhA=", plaintext: "E.T. phone home.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:7p4jwNlMl7i/ka8j0s4ZphioGrjlYZnQnzWAepkCipd8eO0ZC6Cne/nfz+BUag==", plaintext: "Show me the money!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:dQxXInWoQOTrIcqbsMB7kYSvD1yRvxSIl3uz8ZjiOUO8kQYFzarcoCpb/KrgqpQXDbFsjCx0OQ==", plaintext: "You can't handle the truth!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:xv4qMNw1DKWICN64aWb8RLlDzibR43w798ENrOmeh1dKcEpv+05dzdtRm27stg==", plaintext: "I see dead people.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:TRKqa3hb/ixNmiDIc33N17ukS3Li4pn/m6SDToHTqW9RpjTsS9xyFxj5Jj5n86GDCw==", plaintext: "Hasta la vista, baby.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:s31Z6c4a9Xek8fOw9/dpSV0SK1PvPZoTLojCILke/+RAG1VPaZNNi1LUVg==", plaintext: "Why so serious?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:250BZpHxCNBGg3y3jjojauucL8L42bVHqp++xGGqT21odJ603BCW+wJni9LxhodrsD2W", plaintext: "To infinity and beyond!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:7SYMONK/vGtGHGJ6AUjvnjzKEpdtTan4WeklLbsVqxNWJt8+z50t2I59+K+0tXoluEs6Zuahd+/wdxLb4b5KS60=", plaintext: "I feel the need - the need for speed.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:Ua3kvXsdNRF3BzGTa0NvheRdlhm5wKKPumbT/+3RxqUXYd5pqf3kyDX8N0KIfa0=", plaintext: "Just keep swimming.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:Z6w9VIH6TvAgnA47MuvW6xfD2zG+TQioyLlBU6gOhYiqCizQuReV7g==", plaintext: "My precious.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:8Md9h9UbRGYpm/tEMucOiymUjXlLRmIovrKiizL8NFvGNIvm3ghSzp41OulGmtIixMc=", plaintext: "I'm king of the world!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:pkkVMEYsdmrbvgyNMlKbwHPAgBAmpoxCu/mwPf9IklEUq0l8Nuwdur0KSu/u3XcycvtLTPZB8Q==", plaintext: "Elementary, my dear Watson.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:TT4Oyf15oZnFjI5XzRwt9Lt59axFxaXbXS87R9XYEwSW4xnMis2EgcMIJduOtvd1BN/e4fLuxQ==", plaintext: "There's no place like home.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:7PPZW8yYMyTSjGI7dtarQmjcmx1Oc91gdLtmAvei0cxK3ALsxY1TYI/p7LCSprKycTEcSdfS", plaintext: "I'm the king of the world!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:qRq03b8hZBvWPgHheyeWXN6wqtIaxMCvoRtKwQQl77Faw898NWKqy2IAB9I9jrlifayg4mUvkFih8N9Z", plaintext: "Carpe diem. Seize the day, boys.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:nTBjYyctxjx3sdnh6aIanbHOlTd9HaaU6AkS+qV+glHN2pHQVExKyhm8", plaintext: "Here's Johnny!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:6JoKsnGwBrDOdnyc3NqmsxkKNqTGdbcsamKOtd8jANgyxgaRwOyG8h4TJf6uuqT7jwPP5Vz2O1lCE6nTCoIgbbc4S0xkBQkHtplqSQI=", plaintext: "Keep your friends close, but your enemies closer.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:JT55hfODzR5cTF5eO05gybASM19bnJ/1YBY4QUArqOFOCP9qMiXJRC65myrP", plaintext: "I am your father.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:X74AZhad/X9Ai+jDKZijD3XLqJcG2FZhL6lhwHWSF3/BrbefFB08IylrqJ8ae588KTFS4YX1yfZsnhIGfVQmysZwQbvi6w==", plaintext: "I love the smell of napalm in the morning.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:YB5GI3aGfNg74z26MLQ4FRZTTvl5bmsQHXqkGY7yjTgwh4hcbtIRm7tKSnVl0gixe9W8We1MxT/bbvEbDh8=", plaintext: "The stuff that dreams are made of.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:nrLyKW3Rtb1Qwdid/6lWZKrB/WOQaRor9V5pqlJ7XQbPWbTEFRdWy5pxbQLIvXskOX4TGwsDfiFI", plaintext: "Nobody puts Baby in a corner.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:LUULTBHJadUjO+illhAFDbitgIcCyH54ekSoVOM6Lsc3u5udBPv2aBbPQs2k0wz7", plaintext: "You had me at hello.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:eN5zJ9RlKxd+fYbPO+tRKGQ2NN79eRsGW8XhPWTgA8k4D1zXC2BqMv8L2TxYO6TUb3/r+NiQgg5L6IA=", plaintext: "A martini. Shaken, not stirred.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:RaC4h2MkEU95BaKaKzddfUHnma1zjvApvqcSPl9Bfo4FULdNGXu9R2qYyCgHh1MSxPO0LyO+VJMqxyL38g==", plaintext: "Life is like a box of chocolates.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:aucR108/uPgLElmHddynvUH545EeHng3DJKj9kERqP0bHm4HIWSJ+M22/BCtDz//esR9l2VnZZyMJg==", plaintext: "If you build it, he will come.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:Au+Yy5AIXkRP161IwB92EijOKwmmSYhSzt4WCXmqV8HIjbwBfg8BjUi+VTB+ddJahER/IMze", plaintext: "They call me Mister Tibbs!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:WRPqVLuB1U8NBrjZmxxYVrNcUwVM7ROgwTz4We/kpPOqV47/Diox0TnMzPV9zAJNu6Mm0EvjpUEJT1pJCbsH", plaintext: "I'm walking here! I'm walking here!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:dGY7Bc/zQdzt8KFsQM3oETfPFHfqEYKASL9O2Kdox6OhS8KL8/AAcTF3B4VlU2zQ99XA7c0W2ak=", plaintext: "I'll have what she's having.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:reFPSfqArP8/zV/ti2CJc9eq0H+f6B+YUORpI3xFX7w7/7CWg/cZ6kNAVXEybUtrrFxfMl4g/0K0HgPi2xO9eseq+i2XaP5hZS8=", plaintext: "You can't fight in here! This is the War Room!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:zrji7osAS8413orre7xOxsgZoWE+zq5l4Kugy9/rObddhN6zF8U=", plaintext: "I see you.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:BsipVWQjo4w2bIlb/0ostNfQ29Zvv8YFiT0JwDHyl1g1OijMdttnIdWvQZhDl1H4oLM=", plaintext: "I want to play a game.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:fOR6DdkMbd4pFH7Zi6apmXomaUFh4VlBk8Tnk/Gf81DZWBySWVJIqDzEDTkbVfo9TvXlsxReDh8Exw==", plaintext: "Say hello to my little friend!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:InpKTaO2DrlKNoyT8aH1HJqtmZo7CK24/+1en4+MubPDHCaffrZ6N9quXuwV8q4TThfkA3SDALoRVUnZaPwJ1PtIE8GT3oIG", plaintext: "You is kind. You is smart. You is important.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:BKYJA4jQWv11gzd2NyO7fOjbGMmHnrsao97qnE4kinxirWjtvkptiJZ/JnvDMKz2ohPeTgkbcg/X+tRO7Gco", plaintext: "After all, tomorrow is another day!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:WUFqvDJi3v5sSy1EJiH4c8XOyfclCKYPAi7m4PGJ4hAYYv85KUrlg+2EbmXqxewxlDoOepihVO3lDWv5tXjMkxGUXeLlGN6DelXf5VU=", plaintext: "As God is my witness, I'll never be hungry again.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:Po2qKPv1mXJXPQG2WG8aBlw8bLW0WVb1C9zDmgcFABhu4W0xMP8iU17k10yjmPZsIS7+53RNLomLV9Z/NOxMU9cwrQKbhiCZ2hmW7clDPx+Lsg==", plaintext: "Fasten your seatbelts. It's going to be a bumpy night.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:t2Kh9S214LLKcg9z/I4ff2h0lr6fD2OJu+ZZgXyvJV+d0SVQQWOIrhjQdxEK", plaintext: "Nobody's perfect.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:1ZlaIm6NwJ35fwwsbEQJMlDD2Sc9huS9wiWtp2ysErS/HKgjxSXAcqZ7CIUxKnmQ72UD", plaintext: "Well, nobody's perfect.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:ASllPvdtCNTHg0sXD6Zeg1TdxCIN5Km7o/8KrK1/dJz5TrWr/puOBahjQTvKwukoX5sG", plaintext: "It's alive! It's alive!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:BKe2t9qwNBLufs3kHTV3/a+uswOG2fJPYBdDGRDgdEzAgMcLhMJd6R2frtOhFRVEhdN71QbXIZXZuk9N+CfUxKrvSIXGKoWGuWHMbyr0BHjQsy8NIBnPYg==", plaintext: "They may take our lives, but they'll never take our freedom!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:qHbKjqdLyVpDuk0Ia7QAqGYkW8E5+ig6TaMi1zmK2o0QnISCmweDydYnNor1PYnon4XxS/YJjNP0VFssKA1+mmQVf/khD4HhIlmlfWUOdwwP4Km5HJtOZTIKgfVmWayToODeqmhV/tDBlyk=", plaintext: "You've got to ask yourself one question: 'Do I feel lucky?' Well, do you, punk?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
	}

	cipher := Chacha20poly1305{}

	for _, testcase := range testCases {
		plaintext, err := cipher.Decrypt(testcase.ciphertext, testcase.key)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		if plaintext != testcase.plaintext {
			t.Fatalf(`Plain text value does not match! Want %s, got %s`, testcase.plaintext, plaintext)
		}
	}

	for _, testcase := range testCases {
		ciphertext, err := cipher.Encrypt(testcase.plaintext, testcase.key, "1")
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		plaintext, err := cipher.Decrypt(ciphertext, testcase.key)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		if testcase.plaintext != plaintext {
			t.Fatalf(`Plain text value does not match! Want %s, got %s`, testcase.plaintext, plaintext)
		}
	}
}

func TestRijandel256Decrypt(t *testing.T) {
	// these test cases have ben generated using magento 2.4.6, decrypts with and without init vector.
	testCases := []DecryptTestCase{
		{ciphertext: "0:2:NcVAt3jCPas1YjiEueuX36wisjS/ns41DdE7po+h5Yw=", plaintext: "May the Force be with you.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:TjbK9BvnFmiOuraB9khyA0AetsP+xaOscOzG1iHdREPFdlyyWOgqajQoJCACrDpaG3yhudw+wgDtDf7ztI/pBg==", plaintext: "I'm gonna make him an offer he can't refuse.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:Y21nrBrboo74ihPlM4llANFQ0CnNq/VGKvki1kcMklc=", plaintext: "You talking to me?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:INTKDmCGUszA2pzHrRGer8SHvO8pZLa3HcXUa7Goh64=", plaintext: "Here's looking at you, kid.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:T298L9OJ9YyWLkoEKi34hh6N6c4wMx/2oYnuQo9tgSw=", plaintext: "Go ahead, make my day.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:oNNcIW4Tg1ase4CO84wvC2i7MZ59LobVZ133gvOHluI=", plaintext: "I'll be back.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:jI2tEOlHjiuFzN8hWlTwBXXlyVB8RgUcN30iZMdO8lU=", plaintext: "Houston, we have a problem.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:ckZhFwh3vbzz3YbA0+q6KK9EaSx2/GlU6h8vcpRYHJU=", plaintext: "You're gonna need a bigger boat.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:ki8r+kTu3gWNF2/7iCtMvxUiDCB6IBNz5i7MuYyK5/4=", plaintext: "E.T. phone home.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:0F7IX94FeJkVYGjJdRua2Dyg21zNUiB24IKRsrMoIvM=", plaintext: "Show me the money!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:PIZH3Ai/rQwE/QExNcwtNHbh95Ktl8m79Jj0hOYJu5o=", plaintext: "You can't handle the truth!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:NvPEbdT6RgYGfconEJZzk/OVRRzK8vgg6xLU93UaGrs=", plaintext: "I see dead people.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:ZXiwb3kL/Iuq7VzppUcG7AOdijo4yTg2HdRZGKvfyjE=", plaintext: "Hasta la vista, baby.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:J2AB4bvyuPoSKAC1MmVecZ3GjJ/lhDnnIPSGaFLpJ0I=", plaintext: "Why so serious?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:1fpZ16seaL3j4Ztyi3+Ww4QOuIZwgS8zVkpIsjq5h10=", plaintext: "To infinity and beyond!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:+p5kLbAogj/Kg0gTlBf6odAydZrkq/N+/HvYsmxAFJ/H6ZyGUAAQHJ9taFq3NOri7x4pUMvKxTbX7o4HzaZcdg==", plaintext: "I feel the need - the need for speed.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:jHAoIoSFZHOibtL0I1FjJ0CzEc8ZoD0sXXBz4JYnSlM=", plaintext: "Just keep swimming.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:Dp9f6LGMJatLS8p6WRwyGahDNB/a4h3MvhfTxU6kmGk=", plaintext: "My precious.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:tmyBaFEUB6bNpFnQxmIhlaZBl/JnLJc0Le8X2amEAvo=", plaintext: "I'm king of the world!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:dJzuS/RUMqoBgwolgWsR7vxzRoxHkVmY/mUM29ovze0=", plaintext: "Elementary, my dear Watson.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:rSXiWZCJu1UYuKYbNJB4hIjXwCBtbOMLI/Eqd1oN2Gw=", plaintext: "There's no place like home.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:+XO6UUYDJ2LgWr6Bt7x/Sbdi4u4QqpX9t3kbF/imzhA=", plaintext: "I'm the king of the world!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:FGPPegz7WS7V0mtf4pTU2XQkwws93GjjsnpntlyVCiM=", plaintext: "Carpe diem. Seize the day, boys.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:6Rl3FNb31F4ms20Dt09F60P02u4X1L8eFO/qWXKZpNM=", plaintext: "Here's Johnny!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:v84ZoMBw2PxaXeeQ8CssKhCwBuOyaWZCRNc0EKuZtOXoiv8qkLQdwfjaJz8Y9xvEFHMWJcj3/aSZkN4nPD845w==", plaintext: "Keep your friends close, but your enemies closer.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:NJOdNjbfG1LzUaqzXRrdl1QsNsz5AGhAIdqGc/B3ci8=", plaintext: "I am your father.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:G9WfNnSHRVowhvihgw2SYRbKIfeYKvGLtkF6s9E6qkdwgyiNfqzDMmZBJfYemERfE9/ec3hGcJcFu3NVVmfn1w==", plaintext: "I love the smell of napalm in the morning.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:DCIMzeDnrxXCqhs5/3J2DyBFalp4szc9oVC9WlWNp9MqNZ6uEWN3PUyBc9qbPv7m5EN6tfBr7QurlokHmMb/JA==", plaintext: "The stuff that dreams are made of.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:OhU9AaSci/vML9etsGGdRUQYeunWZ8jsVH1jtxtAM2o=", plaintext: "Nobody puts Baby in a corner.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:ApsOWMz7jaI8R0x6DeGn37BAbobVknyrRrsro4rzZ44=", plaintext: "You had me at hello.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:UcA2kd1KGaxPCqTbrtjMX62toGOOd0sg0MxC2HHXeKw=", plaintext: "A martini. Shaken, not stirred.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:L9Mxe4q/qbOY9iQOzArqorhZ+DlF1NDwid48P6Ib4tS90gO2D0Dhhbo7HEZjsb2fq9Mk68D30gv8WGDSUo1jgA==", plaintext: "Life is like a box of chocolates.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:UpF/OqBCwQ8krcrems085jhmn9kuYKUqgq1zf+B8bXY=", plaintext: "If you build it, he will come.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:l3Ed+gtvVbdcQS64JwT+9IkkGEku1OxkCcTiOATegx0=", plaintext: "They call me Mister Tibbs!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:JSKhAp3iuCGa3Gr47PXrAFeeKoahg+OaOMz1cYX38tnHNIK5AL+LvMGS5AYtlojZxT7AG4lJtG4bcW50YkpGOQ==", plaintext: "I'm walking here! I'm walking here!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:2wFV5h/YKBdBWapqqyRLZs9VgG642n5NKB4d26FPjzo=", plaintext: "I'll have what she's having.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:EfrSgNWy7/2ffhcfvI170nEbvPOdJdBbrlAiSi+/4c5Ilmn1GtUqFiotJVlmRKGeVWMJBgBC5FzpeLnCsIRlhQ==", plaintext: "You can't fight in here! This is the War Room!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:oNLZwJqddWLXX9xB+q+uIKiq+ctxeT+Mf8D+DUsekqw=", plaintext: "I see you.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:WM9ZWphkfqUwzZhYnTygHCgkomW+i4cQ8YEi6ASOfv0=", plaintext: "I want to play a game.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:pZUx0+8OXdEBgbUysg0bMeVs+XLQxt2No9EKCrPXoxA=", plaintext: "Say hello to my little friend!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:7+eWBM7Prh4Xvnr52MoZzjVblkCY0HA9nayeHdHu574ffnj6f4l+vIMtwVaiu+lkFAhIkXpBJhi0IEaP9uTX6A==", plaintext: "You is kind. You is smart. You is important.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:mso3Id8tuvqDH3hzklFIdUISd+IuGDEFGOFtlHUey/6ZJquqcFftUzUJ1yNUfUhOiDHwzaiUi4U27UXUPH0o/g==", plaintext: "After all, tomorrow is another day!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:QZifZXU3kfwg0kNeUQGCvfpSiVwtW9MLmC8ffUhQ43EVFgD2/IErYmZPjahP9HjhtYUUtS8y5K5He4jpUr4pDQ==", plaintext: "As God is my witness, I'll never be hungry again.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:wm/pQG+EzWC3uYHSXxRojOpGfpu5R6TBqoy1BuhO2b8bVMxO65G4XeBAbfT/sMfeIidOHxi0iCe5nyaxTcWPIw==", plaintext: "Fasten your seatbelts. It's going to be a bumpy night.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:NAKAPunX0sBfn/V96eced90crMG+jY18d67FdA6XgHI=", plaintext: "Nobody's perfect.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:aRvI6dlirwlxTyM6HvRXPeroyU6htgZlrJsuwHr77/Y=", plaintext: "Well, nobody's perfect.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:JlcS4uO2KImIT3gOxqKlEu4ez5FQX3iJBE04Y8AUDEU=", plaintext: "It's alive! It's alive!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:07rYEzjcn9Xs+v9nkjg5xKAvbO/4e9sxeOXcV+EGGcW3VVYfYOqitr8HNWZzsZ8B3aUvPuHcT/iWs9PrcHRxlw==", plaintext: "They may take our lives, but they'll never take our freedom!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:4XS9l9t58QnQRy17OSUjY9VRUN7RDQowP4BEgtq2wk+RJOIKzCp5TijqWG04zS8AjDE0hLOLHn31JjZE9wOh7PU4tRmcAOwt2133OEF8Jory4ljxICYf9xpCNzFBbvOG", plaintext: "You've got to ask yourself one question: 'Do I feel lucky?' Well, do you, punk?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:3sV8jGD3ovXaPyHYNXXDqZ15CVZ2NC6k:sjIfRya8XaZMJUVcRBw4WAoIHPNID32kxSuKhK1TfU4=", plaintext: "May the Force be with you.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:coyy2RzwgSdhpYal4uq6Q9QbWuec1OCE:3jiqWzjACIFVtPDqM4gom/feOU8C1qqKNvDzS6AZfsphbC8EBaSx+RDz5qzyL8sgLt3jOzSdFvEA1fChrsPW1A==", plaintext: "I'm gonna make him an offer he can't refuse.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:jT4BpGxirfr3oaq6L6wYg9ru5OQjs3RQ:D/0dJ+6KgRT1amizfoSgapJELnJPyDbdPqRxZu3PdYs=", plaintext: "You talking to me?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:xnxjiqG3RGZVMGVc5b02C9Ryl2cmy2Q3:+C9dTyCik3T0MU/9mJwkxfeMHrkIhktC5caHdLeIB8U=", plaintext: "Here's looking at you, kid.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:iW8H4PSgPZjc6ozqoPdNQPPPFGkkCsqX:2xSX/pvC0A3kxouPx42X869ei3HK/YNo9ZD4qnJe3Xg=", plaintext: "Go ahead, make my day.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:uR433MhTXQ4zstLHFw9LOAJypgpWs9XH:zGkrTf/5Hjfzev114TkF6gIEzq4sIe3KJ4hlIaDzkPY=", plaintext: "I'll be back.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:s7cQQl0eLyqf0R2LyDnjgdt746PLrV0V:46RnNQsKKzU53SXhpRDYjsFqGsLGebd5THPfkuSzbJ4=", plaintext: "Houston, we have a problem.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:GRpaVxZJYFfNqorUSEW7WS4aaIClCebF:/iRAgUXbSOon7nQwG4PWcmJC3zIz8f2Rg7aLnMgFCZ8=", plaintext: "You're gonna need a bigger boat.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:QexTr7WDUFQzfd6vtbCGUqYQ0w4SrVcU:sToNWLK9bSIZ8rDMtCotPxHcaxZFhpj1bslbvrfqbaU=", plaintext: "E.T. phone home.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:f9SLzKiwfC5wYqBTGIvtjiniIGFCRLcw:8LneFrt3yfLxdYBkAvuYMwx0J2a8o/+wJmgOc8rfDSY=", plaintext: "Show me the money!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:vVrPKu4J00mgPE4MUSuCSdA2ZKGCUlNB:tYX2xLpZ5lhz0GnPRMxw3+ujpAgctdTOphBBCsuIVHg=", plaintext: "You can't handle the truth!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:Bbufm7j6BBbK7tDrKEhYeUhFDSrp5odN:3e/n52FpzQ4MfD5HtF7NAcz6NpyqDJTeOojQe1u7IYQ=", plaintext: "I see dead people.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:ccBSe5hRqiXeZdpgHdvnAoop0kgf5sCu:VttNuBo6u6HTOnAkYIY8vCYrL44Gn2UJbQdCpDjxm24=", plaintext: "Hasta la vista, baby.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:xsHQIsh5q2vqFY7T42x5vrswTWMyF8dX:Jc3TRSeccZhutPHUKOzCe/YyWLx/Di4r8NTPPnMaZZ0=", plaintext: "Why so serious?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:ixdpf06mJrEUstZiVjDUmxijivXbSUeC:fpbRyrgrm0vdh4UPgJMFlYM0RZBeRMywMSMMHf1Dch0=", plaintext: "To infinity and beyond!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:O1muonQsIpbCc674cf3fClQuKv45mRIu:PsVscKZFoDli9Fz3UQlv9KCY8mfOzBAcLAUUrSiozrF9+HIyfbZPHmePWo3QeKhMMrQbRVWQYL2LVENYysSg+w==", plaintext: "I feel the need - the need for speed.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:NqL00ITXr8sdQUhvQjDcChrJc0uzsUH6:UYXV4eB71lpXp2swMwp9zH7RgdjelNXf0zvdsBORAI4=", plaintext: "Just keep swimming.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:k8SB6xYaHcx2IcJ26gzZZgZQrGEhw5KD:WFInmiAVw1fyuBw8iZyy60eg2qgDcWRmDjcnIBXcZrw=", plaintext: "My precious.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:VvUXH8oG4jE2VUM61AlFWfs2euMUIS4W:/LK4f3+BCjsx9RlMGdTrMDW9Gbv8R9519GdCxHexh0U=", plaintext: "I'm king of the world!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:yHXOAP9dCfz4o4zbwregpHb7bVVu8qVq:P+lXqJBz+tEOYtMPf4vw9W1LWo//uoTj7nWtymWiu6E=", plaintext: "Elementary, my dear Watson.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:cEnd9iDABGhFbOkQnFP3Ym0RTkINKniO:0bCHpM0gh59Az+beWkfIMz0IaDAmh4lNPyQNry2pPRo=", plaintext: "There's no place like home.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:4ElwzFgC1Qqr8kM5q5xIEyQ9k9lIV4vB:usZeuowenX3J9xM35XOC5M51lbbBKwSBDlwrq5I+jd8=", plaintext: "I'm the king of the world!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:agHhwpDSuDNnRNs2cRv3TL9bHIzutMEt:QEvskcKJnBobhvf7zxJnVSEqmnukS/gp3lsZ4KPZd6I=", plaintext: "Carpe diem. Seize the day, boys.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:0DsoxPeOyMNpYyW0e8TZDgkmpq5IChP8:YpCKYzJtgwBpI3sNwWFTNaT7aMMXoKq76XGqPieXZ4U=", plaintext: "Here's Johnny!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:4JMBZlHo04sqm3lV2Dwb7Yt1ibjArRzq:5N+Ve6qVPztkDYsBu+jCDWlX4xcfk9+ff0mYfGPEkGxTNVo/9qAqzRnCcOLzZ7/30BdE+zoxIGpscucmZPOAhg==", plaintext: "Keep your friends close, but your enemies closer.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:XhIIeNtANlJ3QDhhwIr5Vk17zMTkVMdd:U6aaR8d7gvx+MsoMvzLON0Q3EiNyz4PjfKaw9/i3b+s=", plaintext: "I am your father.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:twXfM7zUHOQBvKELQ9PWyAeOA6EujEyd:dmeGNyV079Ap0X8cvBiGuoD9a0U2xvs8f3WiIm7fRp7KlGzn6u1BnCnzd3kM5oVkhbQppN/KrIXnQh0R6+kIPg==", plaintext: "I love the smell of napalm in the morning.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:294iIp5TzR91GR3YC7UUAMmvWYCwC41X:UgCtfJjQ3C8nRPNdg5azRfSCmiGNktX/k+b0EwAn6C6qgV9RlTzMpBWAtsCGin9Oi2KODddWwo+jE6+wlOf8nA==", plaintext: "The stuff that dreams are made of.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:29HNcJwlKaj0HfEflYKoxX9mdjM5hJBG:DD2Qqdo0dI1LTocQDbiAHYlY14K6PbUmX5Yf4batfh0=", plaintext: "Nobody puts Baby in a corner.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:aXy3hLq7S8a5Tocjl617UlPDFNmnAZAb:TZplVWHRgQrV6zyLqvvMPObcLL3HalGT0qOWoRu0CNM=", plaintext: "You had me at hello.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:fDqPgF3DHnTP6SYRRuVUhdOirqSYJMGI:/sKyWe3Yyv8coziI3cDizyWBk3M25NzfRschLfCm25g=", plaintext: "A martini. Shaken, not stirred.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:YZHUaMMjYXFZk5jMRl8ZT29TVGkyUZub:tOyVFYql1mRhoRpENAe6Jq6xwPrMIEape3P6wAjwSGc2bizz/9IuaosIH2P3YoQVB/LhCayX+I4lqM/awSoSHA==", plaintext: "Life is like a box of chocolates.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:XRIKCSS7KaPBj7ph4WZdpAJP6joPUnFp:iNxf8AEpea+Y20iSljXcccL2GGM55g/CkbOZZKzVuuo=", plaintext: "If you build it, he will come.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:farIwl0I6YBCq6H8RuAbvGTexh6bSViZ:BCBc3ZCXney7EbU/xd7MrhO+iOHwSB/6pfpy4W8qYXI=", plaintext: "They call me Mister Tibbs!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:T9S8Q0ZIDEIINIpu9IKTdouSiKX5bkhk:p0pK+b/cPoX4In/RLg9sIJpRBi9RCvWdIboyEdrINEdLcYkASWh6tuIPV3GEllO2lS2dB821CShItgZNR/cpyA==", plaintext: "I'm walking here! I'm walking here!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:GLVkgvXzhs1XJhcT8J3RkceKFSzmURna:zg5xtDAtnvEwCxxyiODTvyNToFS0v+CyKjUNvkzV4+c=", plaintext: "I'll have what she's having.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:1oym31nrLt2OHtB9RhVwpfAZMyEosiii:G7sN3BnSzvABf587M/1jeCGY+WCvsmvzZ06Zx9WOTk6LznV4F9i5Rck38Sc2EqQtkXRjD9HRBihBZjMgOXCKFw==", plaintext: "You can't fight in here! This is the War Room!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:biPokvWBo2FTwxsXnwgieAYRUQEpxtAD:xerU/34gmMCYgDNxaWtVHeEax7PifRNy8OrpwZpmBpA=", plaintext: "I see you.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:W1GYDITO2XpdKNPotoj9QOhDKjzpDOL3:9RYG0rkESgaoKbsB4i28LlzC/B39PGYmRfnI0Vk7yDI=", plaintext: "I want to play a game.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:TpD9yUeTzTtoDAvdmuFs9JLfjByizG7g:Wle04J7QYnf88s2u3F8bjMyrlhL0jfYLrbC2/EuUeyY=", plaintext: "Say hello to my little friend!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:IsI2mD7QiYf8Ph4LOGhCLQkPB7dsU2OU:SSXPSu8OL29AfrXpe7l51UiS3TmuS7TZtD+X9Tv928v0tkFqvFYsGQAHV+EoGJBS34P4Gc7Q/Q36+ajz3EurMg==", plaintext: "You is kind. You is smart. You is important.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:tHlR8MqOnQSPTq6twThnZeX3woOVrZKR:YZyDl4hfuN3RKL8yOOEBWF//sbVOUhE+E5Q6t53MJnuZrY7Vqxjq4lVBc0EfOuEbekMPbs5z1QBPquzUWVfd4g==", plaintext: "After all, tomorrow is another day!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:mS1tvbA1RW6hCQKahih5TbK9xXg1c3jy:KvdYX+F9bb1QjEF2iOzJTbTiCVQsY32RKhMuhLVF9j4TLqVi4W5yEVDpsh7HFJkAWTl8WGrvJx4U9OOHk0M4zw==", plaintext: "As God is my witness, I'll never be hungry again.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:QfQRtQvtVuxv5I3a4WEEv0Io5z0ywQYG:u30Z9STcijr5XiZzIr9FdoRBaFGFSwqTEJ556xRjeZIFchFcLXXfcRhHEa8b+OTFrCYbhWqfRL3spUNlxu7v1g==", plaintext: "Fasten your seatbelts. It's going to be a bumpy night.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:oDLwE0mSDmNXPLYg0sY9EXE0nf1nJsL6:fLtGOd9vQJD6TUz4uL6yjWapoYWmjFjuifuz9IR1fiE=", plaintext: "Nobody's perfect.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:vSrarSLG01UwZsdoIdRWumG9vV3KcN9R:K5BdXZw8COS2ESBM1VwkR2kq4/ZI8xtNn9sVg/TAX/Q=", plaintext: "Well, nobody's perfect.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:ChI1D9RKU2OeqjsOl2UvSMZ2k2iQQ3A8:nY3XLjZbkNaOoWMNkonp5LVgXihAQBBknoFay3i+yP4=", plaintext: "It's alive! It's alive!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:u7ZYB7WkF5PcyZfAVbkyEXwLP43f2zbz:ybA6WqHLp2UWh80RfSZAj5GfSu8cQYlwrC2aeJVMQgxA/DU/SPc/VTimocSbL5SmxaLh5BG+0BpLei08zSdvww==", plaintext: "They may take our lives, but they'll never take our freedom!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "0:2:RVYYphRMxHaohEDUROH82fwYvteFGTAp:V8sF359GdUswaq2/IRBfywiTL0SWyGLJwjOE+NskTtO37fOpvktQtIuZTWpcjPMtfoizdeSGlPpuemEj/eIXEOkGilRIfcXD+9k+VpaERqmt7aXkSOrOySUwTY36eC5w", plaintext: "You've got to ask yourself one question: 'Do I feel lucky?' Well, do you, punk?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
	}

	cipher := NewRijandel256()

	for _, testcase := range testCases {
		plaintext, err := cipher.Decrypt(testcase.ciphertext, testcase.key)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		if plaintext != testcase.plaintext {
			t.Fatalf(`Plain text value does not match! Want %s, got %s`, testcase.plaintext, plaintext)
		}
	}

	for _, testcase := range testCases {
		ciphertext, err := cipher.Encrypt(testcase.plaintext, testcase.key, "1")
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		plaintext, err := cipher.Decrypt(ciphertext, testcase.key)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		if testcase.plaintext != plaintext {
			t.Fatalf(`Plain text value does not match! Want %s, got %s`, testcase.plaintext, plaintext)
		}
	}
}

type GetCipherByValueTestCase struct {
	name           string
	value          string
	expectedCipher Cipher
	wantErr        bool
}

func TestGetCipherByValue(t *testing.T) {
	rijandelCipher := NewRijandel256()
	chachaCipher := Chacha20poly1305{}

	testcases := []GetCipherByValueTestCase{
		{name: "encrypted value with 4 parts", value: "0:2:twXfM7zUHOQBvKELQ9PWyAeOA6EujEyd:dmeGNyV079Ap0X8cvBiGuoD9a0U2xvs8f3WiIm7fRp7KlGzn6u1BnCnzd3kM5oVkhbQppN/KrIXnQh0R6+kIPg==", expectedCipher: rijandelCipher, wantErr: false},
		{name: "encrypted value with 3 parts rijandael cipher", value: "0:2:dJzuS/RUMqoBgwolgWsR7vxzRoxHkVmY/mUM29ovze0=", expectedCipher: rijandelCipher, wantErr: false},
		{name: "encrypted value with 3 parts chacha cipher", value: "1:3:VGPrZUdRHxGAY9y932dC1u67eoEcAx/gVNqj4CXaxFpZac6Jw+pardKnOk3z93vnFf0=", expectedCipher: chachaCipher, wantErr: false},
		{name: "encrypted value with 1 part", value: "VGPrZUdRHxGAY9y932dC1u67eoEcAx/gVNqj4CXaxFpZac6Jw+pardKnOk3z93vnFf0=", expectedCipher: nil, wantErr: true},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := GetCipherByValue(tt.value)

			if (err != nil) && tt.wantErr == false {
				t.Fatalf("Expected no error instead got %v", err)
			}

			if fmt.Sprint(cipher) != fmt.Sprint(tt.expectedCipher) {
				t.Fatalf("Expected cipher %v, got %v", tt.expectedCipher, cipher)
			}
		})
	}
}
