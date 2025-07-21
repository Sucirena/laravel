<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class RiwayatAktivitas extends Model
{
    use HasFactory;

    protected $table = 'riwayat_aktivitas';
    
    protected $fillable = [
        'id_pasien', 
        'id_aktivitas_positif'
    ];

    /**
     * Relasi dengan Pasien.
     */
    public function pasien()
    {
        return $this->belongsTo(Pasien::class, 'id_pasien');
    }

    /**
     * Relasi dengan AktivitasPositif.
     */
    public function aktivitasPositif()
    {
        return $this->belongsTo(AktivitasPositif::class, 'id_aktivitas_positif');
    }
}
