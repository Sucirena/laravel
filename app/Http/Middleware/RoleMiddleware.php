<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class RoleMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @param  string  $role
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next, string $role)
    {
        if (!Auth::check()) {
            // Jika belum login, redirect ke halaman login
            return redirect()->route('login')->with('error', 'Anda harus login terlebih dahulu.');
        }
    
        $user = Auth::user();
        
    
        // Pastikan pengguna memiliki relasi admin jika diperlukan
        if ($role === 'superadmin' || $role === 'content admin') {
            if (!$user->admin || $user->admin->admin_role !== $role) {
                return back()->with('error', 'Anda tidak memiliki akses admin ke halaman ini.');
            }
        } elseif ($user->role !== $role) {
            // Periksa role lainnya
            return back()->with('error', 'Anda tidak memiliki akses ke halaman ini.');
        }

        // Jika semua pemeriksaan lolos, lanjutkan permintaan
        return $next($request);
    }
}
