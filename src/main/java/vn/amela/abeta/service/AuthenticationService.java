package vn.amela.abeta.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import vn.amela.abeta.config.JwtProvider;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserDetailsService userDetailsService;

    private final AuthenticationManager authenticationManager;

    private final JwtProvider jwtProvider;


    public String login(String email, String password) {
        // authenticate process
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));

        // get user info to add to payload
        var userDetails = userDetailsService.loadUserByUsername(email);

        return jwtProvider.generateToken(userDetails);
    }
}
