package msz.Message;

public class Rating implements Message {
    private final Reputationtoken RT;
    private final String randomNumber;
    private final int rating;

    public Rating(Reputationtoken RT, String randomNumber, int rating) {
        this.RT = RT;
        this.randomNumber = randomNumber;
        this.rating = rating;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }

    @Override
    public byte[] getSignature() {
        return new byte[0];
    }
}
