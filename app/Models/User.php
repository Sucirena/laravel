<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;


class User extends Authenticatable implements MustVerifyEmail
{
    use HasFactory, Notifiable;

    protected $table = 'user';
    
    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'role',
        'email',
        'password',
        'nama',
        'jenis_kelamin',
        'tanggal_lahir',
        'foto_profil',
        'otp_code', 
        'otp_expires_at',
        'email_verified_at'
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array{
        return [
            'password' => 'hashed',
            'tanggal_lahir' => 'datetime',
            'otp_expires_at' => 'datetime',
            'email_verified_at' => 'datetime',
        ];
    }

    public function generateOtp()
    {
        $this->otp_code = random_int(100000, 999999); // Kode OTP 6 digit
        $this->otp_expires_at = Carbon::now()->addMinutes(2); // Berlaku 3 menit
        $this->save();
    }

    public function isPremium()
    {
        // Cek langganan aktif
        $activeSubscription = DB::table('subscriptions')
            ->where('id_user', $this->id) // ID pengguna ini
            ->where('ends_at', '>=', Carbon::now()) // Masih dalam masa berlaku
            ->exists();

        return $activeSubscription;
    }

    public function userRemainingPremiumTime()
    {
        // Ambil langganan aktif
        $activeSubscription = DB::table('subscriptions')
            ->where('id_user', $this->id)
            ->select('ends_at')
            ->first();
    
        if ($activeSubscription) {
            $endsAt = Carbon::parse($activeSubscription->ends_at);
    
            // Hitung sisa waktu hanya jika endsAt di masa depan
            if (Carbon::now()->lessThanOrEqualTo($endsAt)) {
                $now = Carbon::now();
                $totalSeconds = $now->diffInSeconds($endsAt);
    
                // Hitung sisa hari, jam, menit, detik
                $days = floor($totalSeconds / 86400); // 1 hari = 86400 detik
                $hours = floor(($totalSeconds % 86400) / 3600); // Sisa jam setelah hari
                $minutes = floor(($totalSeconds % 3600) / 60); // Sisa menit setelah jam
                $seconds = $totalSeconds % 60; // Sisa detik
    
                // Format hasil berdasarkan apa yang tersedia
                if ($days > 0) {
                    return "{$days} hari, {$hours} jam, {$minutes} menit, {$seconds} detik";
                } elseif ($hours > 0) {
                    return "{$hours} jam, {$minutes} menit, {$seconds} detik";
                } elseif ($minutes > 0) {
                    return "{$minutes} menit, {$seconds} detik";
                } else {
                    return "{$seconds} detik";
                }
            }
        }
    
        // Jika tidak ada langganan aktif atau kadaluarsa
        return '0 detik';
    }
    
    public function premiumEndingSoon()
    {
        // Ambil langganan aktif
        $activeSubscription = DB::table('subscriptions')
            ->where('id_user', $this->id)
            ->where('ends_at', '>=', Carbon::now()) // Masih berlaku
            ->select('ends_at')
            ->first();
    
        if ($activeSubscription) {
            $endsAt = Carbon::parse($activeSubscription->ends_at);
    
            // Pastikan waktu sekarang lebih kecil dari endsAt
            if (Carbon::now()->lessThanOrEqualTo($endsAt)) {
                // Hitung selisih hari
                $remainingDays = Carbon::now()->diffInDays($endsAt);
    
                // Jika kurang dari atau sama dengan 5 hari, kembalikan true
                return $remainingDays <= 5;
            }
        }
    
        return false; // Tidak ada langganan aktif atau sudah kadaluarsa
    }
    
    public function admin()
    {
        return $this->hasOne(Admin::class, 'id_user');
    }

    public function tenagaAhli()
    {
        return $this->hasOne(TenagaAhli::class, 'id_user');
    }

    public function pasien()
    {
        return $this->hasOne(Pasien::class, 'id_user');
    }

    public function konten()
    {
        return $this->hasMany(KontenEdukatif::class, 'id_user');
    }
}
