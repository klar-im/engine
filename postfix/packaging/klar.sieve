# Klar filing rules for Dovecot (global LMTP-delivery script).
#
# Install as a sieve_before script so it runs on every delivery, e.g. in
# dovecot.conf:
#
#   plugin {
#     sieve_before = /etc/dovecot/sieve/klar.sieve
#   }
#
# and create the target mailboxes in the inbox namespace:
#
#   namespace inbox {
#     mailbox Junk      { auto = subscribe  special_use = \Junk }
#     mailbox Marketing { auto = subscribe }
#   }
#
# The milter stamps X-Klar-Label (spam|regular) and X-Klar-Class
# (regular|marketing|gibberish|spam, the 4-class argmax). The spam LABEL wins:
# a spam-labelled message goes to Junk even if its class was marketing.

require ["fileinto"];

if header :is "X-Klar-Label" "spam" {
    fileinto "Junk";
} elsif header :is "X-Klar-Class" "marketing" {
    fileinto "Marketing";
}
