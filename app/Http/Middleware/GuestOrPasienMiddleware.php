<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;

class GuestOrPasienMiddleware
{
    /**
     * Handle an incoming request.
     */
    public function handle($request, Closure $next)
    {
        // Jika pengguna belum login (guest), izinkan akses
        if (!Auth::check()) {
            return $next($request);
        }

        // Jika pengguna login, izinkan hanya jika role = pasien
        if (Auth::user()->role === 'pasien') {
            return $next($request);
        }

        // Jika bukan guest atau pasien, tolak akses
        return redirect()->back()->with('error', 'Anda tidak memiliki akses ke halaman ini.');
    }
}
