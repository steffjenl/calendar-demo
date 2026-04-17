<?php

namespace Tests\Feature\Security;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class EmailVerificationEnforcementTest extends TestCase
{
    use RefreshDatabase;

    public function test_unverified_user_is_blocked_from_dashboard(): void
    {
        $user = User::factory()->unverified()->create();

        $response = $this->actingAs($user)->get(route('dashboard'));

        $response->assertRedirect(route('verification.notice'));
    }

    public function test_verified_user_can_access_dashboard(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->get(route('dashboard'));

        $response->assertOk();
    }

    public function test_unverified_user_is_blocked_from_settings_security(): void
    {
        $user = User::factory()->unverified()->create();

        $response = $this->actingAs($user)->get(route('security.edit'));

        $response->assertRedirect(route('verification.notice'));
    }

    public function test_unverified_user_cannot_delete_profile(): void
    {
        $user = User::factory()->unverified()->create();

        $response = $this->actingAs($user)->delete(route('profile.destroy'), [
            'password' => 'password',
        ]);

        $response->assertRedirect(route('verification.notice'));
        $this->assertDatabaseHas('users', ['id' => $user->id]);
    }

    public function test_unverified_user_cannot_update_password(): void
    {
        $user = User::factory()->unverified()->create();

        $response = $this->actingAs($user)->put(route('user-password.update'), [
            'current_password' => 'password',
            'password' => 'NewSecure@Password1!',
            'password_confirmation' => 'NewSecure@Password1!',
        ]);

        $response->assertRedirect(route('verification.notice'));
    }
}
