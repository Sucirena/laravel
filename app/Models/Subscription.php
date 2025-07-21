<?php

namespace App\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Subscription extends Model
{
    use HasFactory;

    /**
     * Nama tabel yang terkait dengan model ini.
     *
     * @var string
     */
    protected $table = 'subscriptions';

    /**
     * Atribut yang dapat diisi secara massal.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'id_user',
        'started_at',
        'ends_at',
    ];
    
    protected $casts = [
        'started_at' => 'datetime',
        'ends_at' => 'datetime',
    ];

    public function remainingPremiumTime()
    {
        $endsAt = Carbon::parse($this->ends_at);

        if (Carbon::now()->lessThanOrEqualTo($endsAt)) {
            $now = Carbon::now();
            $totalSeconds = $now->diffInSeconds($endsAt);

            $days = floor($totalSeconds / 86400); // 1 hari = 86400 detik
            $hours = floor(($totalSeconds % 86400) / 3600); // Sisa jam setelah hari
            $minutes = floor(($totalSeconds % 3600) / 60); // Sisa menit setelah jam
            $seconds = $totalSeconds % 60; // Sisa detik

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

        return '0 detik'; // Kadaluarsa
    }

    /**
     * Relasi ke model User.
     */
    public function user()
    {
        return $this->belongsTo(User::class, 'id_user');
    }
}
