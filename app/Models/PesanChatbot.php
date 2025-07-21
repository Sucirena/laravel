<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class PesanChatbot extends Model
{
    use HasFactory;

    protected $table = 'pesan_chatbot';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'id_percakapan_chatbot',
        'teks',
        'pengirim',
    ];

    protected $casts = [
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * Relationship: PesanChatbot belongs to PercakapanChatbot.
     */
    public function percakapanChatbot()
    {
        return $this->belongsTo(PercakapanChatbot::class, 'id_percakapan_chatbot');
    }
}
