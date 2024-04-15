rule Detect_KloggerAI {
    meta:
        description = "Detects strings related to keyboard activity in network traffic"
        author = "Nicholas Castaldi"
    strings:
        $domain1 = "api.openai.com"
        $domain2 = "webhook.office.com"
        $s1 = "keyboard"
        $s2 = "keylogger"
        $s3 = "pynput"
	$s4 = "OpenAI"
    condition:
        ($domain1 or $domain2) and ($s1 or $s2 or $s3 or $s4)
}

