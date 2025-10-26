package com.examalchemy.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    // You can access this at http://localhost:8080/api/test/public
    @GetMapping("/public")
    public String publicTest() {
        return "This is a PUBLIC endpoint. Anyone can see this!";
    }

    // You can only access this if you are authenticated
    @GetMapping("/secure")
    public String secureTest() {
        return "This is a SECURE endpoint. You must be logged in.";
    }

    // You can only access this if you are authenticated AND have the 'TEACHER' role
    @GetMapping("/teacher")
    @PreAuthorize("hasRole('TEACHER')")
    public String teacherTest() {
        return "This is a TEACHER-ONLY endpoint.";
    }
}