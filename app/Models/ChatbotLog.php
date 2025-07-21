<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ChatbotLog extends Model
{
    use HasFactory;

    // Nama tabel
    protected $table = 'chatbot_log';

    // Kolom yang dapat diisi (mass assignable)
    protected $fillable = [
        'id_pasien',
        'sent_at',
    ];

    // Tentukan bahwa `sent_at` adalah tipe datetime
    protected $casts = [
        'sent_at' => 'datetime',
    ];

    public $timestamps = false;

    /**
     * Relasi ke model Pasien.
     * Jika `id_pasien` bernilai null, relasi akan menjadi null.
     */
    public function pasien()
    {
        return $this->belongsTo(Pasien::class, 'id_pasien');
    }
}
