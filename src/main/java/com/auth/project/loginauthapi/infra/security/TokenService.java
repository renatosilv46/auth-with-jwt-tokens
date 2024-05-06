package com.auth.project.loginauthapi.infra.security;

import com.auth.project.loginauthapi.domain.user.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    @Value("${api.security.token.secret}")                                              //Valor para indicar que a chave desta var está em outro arquivo;
    private String secret;

    public String generateToken(User user){

        try{

            Algorithm algorithm = Algorithm.HMAC256(secret);                      //Aqui estou definindo que o tipo de criptografia do token será este;

            //Criação do token;
            String token = JWT.create()
                    .withIssuer("login-auth-api")                              //Aplicação responsável pelo token;
                    .withSubject(user.getEmail())                             //Info do usuário que irá receber o token;
                    .withExpiresAt(this.generateExpirationDate())            //Tempo de expiração do token, esta função está chamando um método;
                    .sign(algorithm);                                       //Definindo que o tipo deste token será com a criptografia que defini em cima;
            return token;

        }catch (JWTCreationException exception){
            throw new RuntimeException("Error while authenticating");
        }

    }

    public String validateToken(String token){

        try{

            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("login-auth-api")
                    .build()
                    .verify(token)
                    .getSubject();
        }catch (JWTVerificationException exception){
            return null;
        }
    }

    private Instant generateExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }

}
