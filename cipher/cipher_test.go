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
	// these test cases have ben generated using magento 2.4.6
	testCases := []DecryptTestCase{
		{ciphertext: "1:3:4Ktx5luXlvrR6tBngh7mhniSr23A2yuo:X311I3oz9ZffpcRc0kXgKY8VjXI3yPoYs2Qr1XC1t/w=", plaintext: "May the Force be with you.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:89X67XVMa6XhtHlQEZD9czeRQUDEKL13:Hsastd7+pQVkQ/inLC3yqB1LtQlDIxXk9MPuF7EBVOWDMSYRr0DTMbpKDcfeXYq0wZk2uFeLBQ7m0T3FSOHDNA==", plaintext: "I'm gonna make him an offer he can't refuse.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:WA7AneNyOcZ2zFNuCRirws5uD2q3PQOq:iX8yeJfn7YevRqfJixI4mXkEIA5GWXvJeVj1L01bXDY=", plaintext: "You talking to me?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:qENuBgi4sjMDM27dRlqZt4tlRo5ju4lP:JXhcM985WYGLqoui6dnjOfy1XVc7VkEsDERJ44Cr4Mo=", plaintext: "Here's looking at you, kid.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:nNSwbZNSkwBUIq8Le2GWoNPVtDFHKvh6:m69dgR42niJipV/ZZaDYXWj7m7pUv3UvJ8ICTa+XxzI=", plaintext: "Go ahead, make my day.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:gtZM0t3VyXtMDF0owAIV4U1IvAaQ5Xkb:qJsnVkGW2HqjLxAc9tcWGqs9nN/xWmfkJzKm4Teou9I=", plaintext: "I'll be back.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:1GG8J5UUNW3EPzaBvMrFg1y0hLmrL7md:hC9d1XgN2SmOeKYEw/L1pTtOAqzrezqv9v4q+kTEG7Y=", plaintext: "Houston, we have a problem.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:Z6ZOVc7nXhYvhXpmi4JawOPEOcRnmOQO:lt3G4pHWA1nLKPhUVd1fclGpOmxgxrBFo0I+HDhnXr0=", plaintext: "You're gonna need a bigger boat.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:KBmfLVFxNxsEBtAiNbNWqQNXPZV3FWNy:RN7wc5CDfOtSJ+KAXuDSiIBHHnKfR/tLEL3xHQRbb8I=", plaintext: "E.T. phone home.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:sB5Yr3wHoZwToMKfrZaenuykF48Sfahy:BULnOKhqhShF6iGlw6d7SJd9oDHjOUFcFChVjjyvvs8=", plaintext: "Show me the money!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:J63AAFocyKy9Uk2dzmekgxLJjrohqo4C:p0Pvz5hGLiPkoWFYmnI+Q6ABY3ZUP9oJobsSlZkskk0=", plaintext: "You can't handle the truth!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:tmJsMOeF1egaoK0i5sCgJUyGPrOf5qs7:EP7dBXzad0dhL44nrwNqGzIxSDJHmLe4coxvYvOkxg4=", plaintext: "I see dead people.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:Gw0lajM4yuGoavZwXIXmi4noCFsKHcKj:hlRwDNAOvMeJSWKqXvVP4yRU6KuSY5abCi01Eo2np8E=", plaintext: "Hasta la vista, baby.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:EMvbsrntTPhP7VkjURqzarZRx5HUqSWg:ooQh1QSsQIXuDpwGe27j7TZWEIoxDltJ2PhiDD53BDs=", plaintext: "Why so serious?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:6Lo542UljLFfgEjNTnVEWnAxnDnPFeSR:BmfLrV/ayFGI9zBLFB3lPytqjfS/n/JBn189odkQdIQ=", plaintext: "To infinity and beyond!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:LhDtYJ0BCZUEIxUbbV55Fyw0Mq5bhjxe:TrwfZ4JwX3Z+fbbuIGfGKSV0/nTtBmoAdRhu6fubXEfYlDVIk+3HUdvAwOPBrScIT7fbCD4+PPH08Wlz4mOa+w==", plaintext: "I feel the need - the need for speed.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:FiHt0zqoRm5we2qCEB28oQyUA6g5ysAc:NQVo/+WL2WKUOGxIXMuaCaRP6nTeqKoE+48yiaxpx2Y=", plaintext: "Just keep swimming.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:lViGTMNGJo639CQEDII2D8STbics700V:PbOt24GdMsFgdgll4I5a+IBJ6kgA8SnGi+djnjG+msE=", plaintext: "My precious.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:DvbaN9LZ58qPYYiCMLPXkEHWpFz191qn:9lAAFFgTGtZ0N7AHWzqxb9hrdDnRvO15OsxZvHOiUa8=", plaintext: "I'm king of the world!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:ig3f4F1Hn9V3d8WacU8Hzing0iHq8ei1:N8Q78D5r6kQZkvDfj3feS90oa1bOvMpLx+eFCqh9+Xw=", plaintext: "Elementary, my dear Watson.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:MVTaSoMEkrb3mC78kMoa2uuc1F9C4y3z:WijEM0opioTl8JVR2YD2Ap9ZkfadkGhREk7zuFJM8j0=", plaintext: "There's no place like home.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:4bzcNvH2VDLhwKjSFF7cYuzsCbFEJpEH:ts0uUKQC60s7iCEBMzQ4MKK4KPzTXTOJwSEBoH0fxJA=", plaintext: "I'm the king of the world!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:MXuvljgMuCjGGpYbFZ5nmcCI415KBagz:LJS1R1ZA315KPHgU2vT89eJo4bq3oFLU0hvpSzygEUM=", plaintext: "Carpe diem. Seize the day, boys.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:pQxtDW683pvSxPaalvNBqffOocnvj8Z7:HRbpuQJ/0AeYLy5JubD4xI10cvfmCL7qrG3VX5Kk90I=", plaintext: "Here's Johnny!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:ZU0byef9Pb2XPCQDI5vGZ4DkZigoFwpg:EmCj++CDNTlvS9c2K9y8spTjVCO7yV5dpnEvXzmW02I04ewfxdymGCXswmZciMv2bD31RRXT/iUpAugnuE90aA==", plaintext: "Keep your friends close, but your enemies closer.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:DnlLeiMy462CaH8XHKIC09YvN9ntj3Jx:vxGIraM+JpaY9aQpZrr3nBsDwBTob0xsHv8fvtBY3gM=", plaintext: "I am your father.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:sNsyrGoj2Kby94FLoY1yQ9HG9mN8v6PU:NRe+wuMktJ53NS5vEOXi2fv03R6uA0UJM4X54emjl7Cm0XLo5LJIfJgf8nbKjC7dX7egRdOTus+UaFLtzSXVMA==", plaintext: "I love the smell of napalm in the morning.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:WRdzVSQcYRA3TG7R3LTGDT5sEkN0KJlg:YxL81AqR6uof/IDy8P0x8qxM6WlMzdt3+Hejdw+kbjREZXmHkL4RKkkRyFTnbOq/rYlxArZXRWLXr7owkRBrOw==", plaintext: "The stuff that dreams are made of.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:CJlJ96JTWPPL1mONIdQzLgVqlTyfJuzP:EmgU+VPKBeenQNKB8+vdcscnUGd9wKGafHdFZ0lgaxk=", plaintext: "Nobody puts Baby in a corner.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:cGslrPWvG2rqxbG9MIAzry5uzraFiF6n:PFy7pnkj2v2FeGyeYNKJOqcURDGHrk+9HXrFiXNj97g=", plaintext: "You had me at hello.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:H65jR3WUSLzREAjv6lPR0nBxdjfuAO4t:cxUnyPduWB3DONj6a+CEken0YLRirPqrv1Hsfue51jE=", plaintext: "A martini. Shaken, not stirred.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:4roPyVAiiTNYHf6rBIVrWTPh6vPxMIDn:vjvx+6ZfiAEfed+jmLzHywuNLDGwYZTuH25mhZdwTGGsNKeWSJVA3sMGe8EQKdIWOPFt4zQwjih+xQWdLP4bZw==", plaintext: "Life is like a box of chocolates.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:Wb4pQA8XHheAbUf8tuODBVRITsctmNTV:pKfrnBhTpiLG573XHMn164oj+7BrYTnmRJqSRn8YcVQ=", plaintext: "If you build it, he will come.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:98pjWsKfYgUirWBEB5qBZCJpTqmz16pk:28ZX4oE7aaIBYUJLw7Du8WwJXxH4NcTD6Xr/dAiBONc=", plaintext: "They call me Mister Tibbs!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:LTMcuwWCZoJcGMi98Jw2G0CMa7oYGAyG:Ula2orM5MleOKEalhY46S/6lkYJpYoNH0f3/j05C0KLguvWa9SYKFh7wwLyG2btmofImqdHG38Wn29huAVHMmQ==", plaintext: "I'm walking here! I'm walking here!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:OZ6t9pY9ygV6q0DJ6mtbGEDfpOy5iQZy:WI9DLAG3wkPx7HRezDseTS2YM9oOsyY+J9/FSImTQ6c=", plaintext: "I'll have what she's having.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:coZmVB7V5QcbrOwNzVfVwytOf0tdkfpA:JgOWGh2uNxfQa5pAC6FFUdpMPOiYC5j2sbopLXenFBnnPjm86IUjUPWJF5pIhWpkata5dkx1rzYiHfGmxHHBHA==", plaintext: "You can't fight in here! This is the War Room!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:QKTeSDZXXwkQwL83XYfniyaDLwAGOEF5:eGrolS6Jy3Dqtfw5VGfty+BnNnkjdRn0E5BDPCkNXDY=", plaintext: "I see you.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:ddvTX6SlZiOhHtKWcj7IdSPfqzfV1GvF:b30QbZWnlklXH94adQyBZiQkFi8hN+qE0OAAWbXokXw=", plaintext: "I want to play a game.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:aV8430eNTZFl2FXwmLzBSaEaqYG9NlqF:X9ti4kOWJozdcZNZJUbfBfYpQ6nLUqrz1yVPkYM0WMs=", plaintext: "Say hello to my little friend!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:REpjXjizswh53TWAQWRIhBJK0VoGACU9:fQzM7ekvWMGhp8gUMuE9MZwl7J4FgxpXoWCe6Ru3foykegiF0/dimdvnVEtFGBh/lvhbv2XH8RAp3xrSbCHkqw==", plaintext: "You is kind. You is smart. You is important.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:hXO7Ats84AOyc9m0V58d8Woi0A6e2WEW:g+43f/EviaGIcAQKnnku0lM7cnwH2AoX2ATxmY7FsuvJSwZSvAmLLEauYGVO5Ye41EmAAYsZfTc90TEhj8ox1A==", plaintext: "After all, tomorrow is another day!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:k5swZU8twinYwCki7rccQHmNngAsOsAC:9quGKOZOnR1cFGjcxaUAIpt8EenR5pfl14twE5HtZ7e5pf4FyTKRCNag2i2IwgptcEIJA0/9jw27vubRGxi17A==", plaintext: "As God is my witness, I'll never be hungry again.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:7ps8YDFaoBBGogRqTut6QwSjaDmzo5Np:ViscA6dnhiVu/YMG0BuNRP25mEMqxGKUTLQzoNMUMwJoUzVOItzprKB7G2Wcly1SoTJQufpxqnDVEEc/52MfXg==", plaintext: "Fasten your seatbelts. It's going to be a bumpy night.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:RzkcMtYnvpYn65vVFM7PsT0Ns9hEq7hV:QgWHpTnV7Yk/KJYnpRnQ3dwMZSpsvRmyrMQR+pvnz4Y=", plaintext: "Nobody's perfect.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:bNVSx3XRaiiwjzSLUY1KrLOoe4xnJStV:JAfD5E7D+xymLQ5kiDPSKZaBNwCEXiW8GjdzdWd8qsw=", plaintext: "Well, nobody's perfect.", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:kliQfkG2HI1sUcKFGLVCEFLsLny2QcWB:pFtXXVcEq4QfITBm+U//p7UB649/4cTes5ltye9Nl/c=", plaintext: "It's alive! It's alive!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:q7BQlfCUkj8DGP7xx3q8zbG2ovnbm5JO:307GKJVJvmta9Sp/Oo9zRlhRi071R+6b+TI9Z865N8O6PuTCUMU/Hpc9w4RSyjQ450kcbZrHznqW2aOjz4B08Q==", plaintext: "They may take our lives, but they'll never take our freedom!", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
		{ciphertext: "1:3:W8B7ZUXGY4cRs7ZxU9HQ9vFCCDC7TFlp:eW1MUF6WPB7I6IpdNPJYUS9goWG0pehi9+ePIM5Pb8kdwYAElSRaod6FyOSNjoiqDCUTrYfoOyXAJkSqPgxwyEB90Kr8AeuESo026kvHXhyyYBBXhQZ5owYpGfYLPLj0", plaintext: "You've got to ask yourself one question: 'Do I feel lucky?' Well, do you, punk?", key: "e331b68cf8e8646f09e6ddcad2d32d83"},
	}

	cipher := Rijandel256{}

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
