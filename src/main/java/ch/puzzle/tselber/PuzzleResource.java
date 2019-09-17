package ch.puzzle.tselber;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

@Path("/")
public class PuzzleResource {


    private static final String ICE_DRAGON = "ICE_DRAGON";
    private final Logger logger = LoggerFactory.getLogger(PuzzleResource.class);

    private JWTVerifier verifier;

    @ConfigProperty(name = "ice.dragon.secret")
    String sharedSecret;

    @ConfigProperty(name = "puzzle.secret")
    String puzzleSecret;

    @ConfigProperty(name = "puzzle.words")
    String words;

    @ConfigProperty(name = "puzzle.account")
    String account;

    @ConfigProperty(name = "puzzle.index")
    String index;

    @PostConstruct
    public void init() {
        Algorithm algorithm = Algorithm.HMAC512(sharedSecret);
        verifier = JWT.require(algorithm)
                .build();
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    public InputStream puzzle(@CookieParam(ICE_DRAGON) Cookie cookie, @QueryParam("secret") String secret) throws FileNotFoundException {
        String iceDragon = Optional.ofNullable(cookie)
                .map(Cookie::getValue)
                .orElse(null);
        try {
            logger.info("Provided ice dragon: " + iceDragon);
            DecodedJWT jwt = verifier.verify(iceDragon);
            logger.info(jwt.getExpiresAt() + " " + jwt.getExpiresAt().after(new Date()));
            if (jwt.getExpiresAt().after(new Date())) {
                if (puzzleSecret.equals(secret)) {
                    return new FileInputStream(Paths.get("secret.html").toFile());
                } else {
                    return new FileInputStream(Paths.get("secret-missing.html").toFile());
                }
            } else {
                logger.info("Too late for that cookie");
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.info("Wrong cookie!");
        }
        return new FileInputStream(Paths.get("hello.html").toFile());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Words puzzleJson(@CookieParam(ICE_DRAGON) Cookie cookie, @QueryParam("secret") String secret) {
        String iceDragon = Optional.ofNullable(cookie)
                .map(Cookie::getValue)
                .orElse(null);
        try {
            logger.info("Provided ice dragon: " + iceDragon);
            DecodedJWT jwt = verifier.verify(iceDragon);
            logger.info(jwt.getExpiresAt() + " " + jwt.getExpiresAt().after(new Date()));
            if (jwt.getExpiresAt().after(new Date())) {
                if (puzzleSecret.equals(secret)) {
                    return getWords();
                } else {
                    return getWordsSecretMissing();
                }
            } else {
                logger.info("Too late for that cookie");
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.info("Wrong cookie!");
        }
        return getHelloWords();
    }


    @GET
    @Path("dragons-nest")
    @Consumes(MediaType.TEXT_PLAIN)
    public Response setDragonNest(@QueryParam("voucher") String iceDragon) {
        NewCookie cookie = new NewCookie(ICE_DRAGON, iceDragon);
        return Response.ok().cookie(cookie).build();
    }

    private Words getHelloWords() {
        Words words = new Words();
        words.words = new String[] {"hello","are","you","lost?"};
        return words;
    }


    private Words getWordsSecretMissing() {
        Words words = new Words();
        words.words = new String[] {"you","are","missing","a","?secret=","maybe?"};
        return words;
    }

    private Words getWords() {
        Words words = new Words();
        words.words = this.words.split("[,\\s]");
        words.account = account;
        words.index = index;
        return words;
    }
}