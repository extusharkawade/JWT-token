package io.getarrays.userservice.repo;

import io.getarrays.userservice.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<User,Long> {

    @Query(value = "select * from user where username=:username",nativeQuery = true)
    User findByusername(String username);
}
