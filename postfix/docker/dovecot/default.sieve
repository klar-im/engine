require ["fileinto"];

if header :is "X-Klar-Label" "spam" {
    fileinto "Junk";
} elsif header :is "X-Klar-Class" "marketing" {
    fileinto "Marketing";
}
