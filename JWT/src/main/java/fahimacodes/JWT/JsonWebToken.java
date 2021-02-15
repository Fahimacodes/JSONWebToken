package fahimacodes.JWT;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * Generate, verify, decode a JSON Web Token for representing claims securely
 * between two parties. Originally used for Zoom JWT App. https://jwt.io/
 * https://github.com/auth0/java-jwt
 * 
 * @author fahimacodes
 */
public class JsonWebToken {

	public static void main(String[] args) throws ParseException {

		String apiKey = "API KEY FROM JWT APP";
		String apiSecret = "API SECRET FROM JWT APP";

		String token = createJWT(apiKey, apiSecret);
		verifyJWT(token, apiKey, apiSecret);
		decodeJWT(token);
	}

	// Generate JSON Web Token
	private static String createJWT(String apiKey, String apiSecret) throws ParseException {
		String JSONWebToken = null;
		// Convert from human-readable date to epoch to create expiry time stamp
		long expires = new SimpleDateFormat("HH:mm:ss MM/dd/yyyy").parse("00:00:00 02/01/2022").getTime() / 1000;
		Date expiresAt = new Date(expires * 1000);
		Date issuedAt = new Date();

		Algorithm algorithm = Algorithm.HMAC256(apiSecret);
		JSONWebToken = JWT.create().withIssuer(apiKey).withAudience("null").withExpiresAt(expiresAt)
				.withIssuedAt(issuedAt).sign(algorithm);

		System.out.print("Generated JSON Web Token: " + JSONWebToken);
		return JSONWebToken;
	}

	// Verify JSON Web Token
	private static void verifyJWT(String token, String apiKey, String apiSecret) {
		try {
			Algorithm algorithm = Algorithm.HMAC256(apiSecret);
			JWTVerifier verifier = JWT.require(algorithm).withIssuer(apiKey).build();
			DecodedJWT jwt = verifier.verify(token);
		} catch (JWTVerificationException exception) {
			// If the token has an invalid signature or the Claim requirement is not met, a
			// JWTVerificationException will raise.
			System.out.print("Invalid signature/claims" + exception.getMessage());
		}
	}

	// Decode JSON Web Token
	private static void decodeJWT(String token) {
		try {
			DecodedJWT jwt = JWT.decode(token);
		} catch (JWTVerificationException exception) {
			// If the token has an invalid syntax or the header or payload are not JSONs, a
			// JWTDecodeException will raise.
			System.out.print("Invalid token" + exception.getMessage());
		}
	}
}
