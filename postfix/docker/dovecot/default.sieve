require ["fileinto"];

if header :is "X-Klar-Label" "spam" {
    fileinto "Junk";
}
