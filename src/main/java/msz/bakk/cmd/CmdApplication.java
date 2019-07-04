package msz.bakk.cmd;

import org.jline.utils.AttributedString;
import org.jline.utils.AttributedStyle;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.shell.jline.PromptProvider;


@TestConfiguration
@SpringBootApplication
public class CmdApplication {

    public static String shellprefix = "WoN";

    public static void main(String[] args) {
        if(args[0] != null) {
            shellprefix = args[0];
        }

        SpringApplication.run(CmdApplication.class, args);
    }

    @Bean
    public PromptProvider myPromptProvider() {
        return () -> new AttributedString(shellprefix+":>", AttributedStyle.DEFAULT.foreground(AttributedStyle.YELLOW));
    }
}
