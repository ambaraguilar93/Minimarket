package com.minimarket.controller;

import com.minimarket.entity.Rol;
import com.minimarket.entity.Usuario;
import com.minimarket.repository.RolRepository;
import com.minimarket.repository.UsuarioRepository;
import com.minimarket.security.model.CustomUserDetails;
import com.minimarket.security.model.LoginRequest;
import com.minimarket.security.util.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {

        private final AuthenticationManager authenticationManager;
        private final JwtUtil jwtUtil;
        private final UsuarioRepository usuarioRepository;
        private final RolRepository rolRepository;
        private final PasswordEncoder passwordEncoder;

        public AuthController(
                        AuthenticationManager authenticationManager,
                        JwtUtil jwtUtil,
                        UsuarioRepository usuarioRepository,
                        RolRepository rolRepository,
                        PasswordEncoder passwordEncoder) {

                this.authenticationManager = authenticationManager;
                this.jwtUtil = jwtUtil;
                this.usuarioRepository = usuarioRepository;
                this.rolRepository = rolRepository;
                this.passwordEncoder = passwordEncoder;
        }

        // LOGIN
        @PostMapping("/login")
        public String login(
                        @RequestBody LoginRequest request) {

                System.out.println("LOGIN INTENTANDO");
                System.out.println(request.getUsername());
                System.out.println(request.getPassword());

                try {

                        authenticationManager.authenticate(
                                        new UsernamePasswordAuthenticationToken(
                                                        request.getUsername(),
                                                        request.getPassword()));

                        System.out.println("LOGIN EXITOSO");

                } catch (Exception e) {

                        e.printStackTrace();

                        throw e;
                }

                Usuario usuario = usuarioRepository
                                .findByUsername(request.getUsername())
                                .orElseThrow();

                return jwtUtil.generateToken(
                                new CustomUserDetails(usuario));
        }

        // REGISTER
        @PostMapping("/register")
        public String register(
                        @RequestBody Usuario usuario) {

                usuario.setPassword(
                                passwordEncoder.encode(usuario.getPassword()));

                // ASIGNAR ROL CLIENTE POR DEFECTO
                Rol rolCliente = rolRepository.findByNombre("ROLE_CLIENTE")
                                .orElseThrow();

                usuario.setRoles(Set.of(rolCliente));

                usuarioRepository.save(usuario);

                return "Usuario registrado correctamente";
        }
}
