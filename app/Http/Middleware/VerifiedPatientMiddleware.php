<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Auth;

class VerifiedPatientMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle($request, Closure $next)
    {
        if(Auth::check()){
            $id = Auth::user()->id;
            $user = User::findOrFail($id);

            // Cek apakah pengguna adalah "pasien" dan emailnya sudah diverifikasi
            if (!$user->hasVerifiedEmail()) {
                return redirect()->route('verification.notice')->with('error', 'Verifikasi email anda terlebih dahulu');
            }
        };
        return $next($request);
    }
}
