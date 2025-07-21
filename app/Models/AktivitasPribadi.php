<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AktivitasPribadi extends Model
{
    use HasFactory;

    protected $table = 'aktivitas_pribadi';
    
    protected $fillable = [
        'id_aktivitas_positif', 
        'id_pasien', 
        'is_completed'
    ];

    /**
     * Relasi dengan AktivitasPositif.
     */
    public function aktivitasPositif()
    {
        return $this->belongsTo(AktivitasPositif::class, 'id_aktivitas_positif');
    }

    /**
     * Relasi dengan Pasien.
     */
    public function pasien()
    {
        return $this->belongsTo(Pasien::class, 'id_pasien');
    }

    public $timestamps = false;
}
