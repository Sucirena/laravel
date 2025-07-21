<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;

class PremiumMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // Dapatkan pengguna yang sedang login menggunakan Auth
        $userId = Auth::user()->id;
        $user = User::find($userId);

        // Gunakan metode isPremium pada model User untuk mengecek status premium
        if (!$user->isPremium()) {
            return redirect()->back()->with('error', 'Halaman ini hanya untuk pengguna premium. Silakan berlangganan untuk mendapatkan akses.');
        }

        // Lanjutkan permintaan jika pengguna premium
        return $next($request);
    }
}