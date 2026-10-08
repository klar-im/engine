require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment"];
# Runs on every move out of Junk (imapsieve_mailbox2, dovecot.conf). Deleting
# spam from Junk moves it to Trash: no opinion, not a rescue, the same rule as
# stalwart/scripts/junk_feedback.py and Stalwart's own trainer (TASK-547).
if environment :is "imap.mailbox" "Trash" {
    stop;
}
pipe :copy "klar-feedback" ["ham"];
