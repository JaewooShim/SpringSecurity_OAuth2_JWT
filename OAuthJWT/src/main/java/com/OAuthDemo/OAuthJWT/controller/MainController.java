package com.OAuthDemo.OAuthJWT.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/")
    @ResponseBody
    public String mainPage() {
        return "Main";
    }
}
