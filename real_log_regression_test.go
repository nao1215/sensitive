package embargo_test

import (
	"testing"

	"github.com/nao1215/embargo"
)

func TestOperationalLogFalsePositives(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind embargo.Kind
		text string
	}{
		{embargo.KindSWIFTBIC, "workerEnv.init() ok /etc/httpd/conf/workers2.properties"},
		{embargo.KindSWIFTBIC, "Deleting file /mnt/hadoop/dfs/data/current/subdir58/blk_123"},
		{embargo.KindSWIFTBIC, "rhost=pokemon1.cs.example.net"},
		{embargo.KindPAN, "blockMap updated: blk_-3702595599317472079 size 67108864"},
		{embargo.KindPAN, "03-17 16:16:01.530 28601 28601 V AudioManager: querySoundEffectsEnabled"},
		{embargo.KindMyNumber, "03-17 16:15:06.211  1702 27353 D PowerManagerService: releasing"},
		{embargo.KindMyNumber, "rhost=217-159-208-230-dsl.example.net"},
		{embargo.KindJPPhone, "03-17 16:13:39.070  1702  1815 D WindowManager: startAnimation"},
		{embargo.KindABARouting, "eventTime=261851713, downTime=261851646"},
		{embargo.KindABARouting, "acquire lock=233570404, flags=0x1"},
		{embargo.KindABARouting, "ino=-268435446 scontext=system_u:system_r"},
		{embargo.KindCredential, "token=Token{a64f992 ActivityRecord{de9231d}"},
		{embargo.KindCredential, "Bad activity token: android.os.BinderProxy@2bd79ce"},
	} {
		t.Run(string(tc.kind)+"/"+tc.text, func(t *testing.T) {
			t.Parallel()
			if got := embargo.NewScanner(embargo.WithKinds(tc.kind)).ScanString(tc.text); len(got) != 0 {
				t.Fatalf("operational metadata became a secret: %v", got)
			}
		})
	}
}

func TestCredentialObjectSyntaxStillProtectsPasswords(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
	for _, text := range []string{`password=Example@abcdef12`, `token="Example@abcdef12"`, `secret=Token{abcdef12`, `token=Example@nothex`} {
		if len(scanner.ScanString(text)) != 1 {
			t.Errorf("credential was missed: %s", text)
		}
	}
}

func TestCustomKeyStillFindsOpaqueText(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential), embargo.WithSensitiveKeys("recovery_code"))
	const text = "recovery_code=opaque-recovery-code password=public-label"
	got := scanner.ScanString(text)
	if len(got) != 1 || text[got[0].Start:got[0].End] != "opaque-recovery-code" {
		t.Fatal("custom key did not replace the default text key selection")
	}
}
