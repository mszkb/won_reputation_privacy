package msz.Reputation;

import msz.Message.Reputationtoken;

import java.util.List;

public class ReputationBotClientHandler extends Thread implements IRepuationBot {

    public ReputationBotClientHandler() {
        // TODO cert of client
        // TODO random hash of client
    }

    @Override
    public void run() {
        // TODO switch case to different commands
        String incoming = "part1 part2";
        String[] parts = incoming.split(" ");

        // TODO connection of other bot

        switch (parts[0]) {
            case "randomHash":
        }
    }

    @Override
    public void exchangeRandomHash(String randomHash) {

    }

    @Override
    public void getBlindSignature() {

    }

    @Override
    public void createAndExchangeRepuationToken() {

    }

    @Override
    public void rateTheTransaction() {

    }
}
