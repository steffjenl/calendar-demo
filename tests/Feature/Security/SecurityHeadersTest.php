<?php

namespace Tests\Feature\Security;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class SecurityHeadersTest extends TestCase
{
    use RefreshDatabase;

    public function test_security_headers_are_present_on_web_responses(): void
    {
        $response = $this->get(route('home'));

        $response->assertHeader('X-Frame-Options', 'SAMEORIGIN');
        $response->assertHeader('X-Content-Type-Options', 'nosniff');
        $response->assertHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->assertHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
        $response->assertHeader('X-XSS-Protection', '1; mode=block');
        $response->assertHeader('Content-Security-Policy');
    }

    public function test_csp_header_contains_required_directives(): void
    {
        $response = $this->get(route('home'));

        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString("default-src 'self'", $csp);
        $this->assertStringContainsString("frame-ancestors 'none'", $csp);
        $this->assertStringContainsString("form-action 'self'", $csp);
        $this->assertStringContainsString("object-src 'none'", $csp);
    }

    public function test_hsts_header_is_absent_in_non_production(): void
    {
        // HSTS is only sent over HTTPS in production; never in the test environment
        $response = $this->get(route('home'));

        $this->assertNull($response->headers->get('Strict-Transport-Security'));
    }
}
